#ifndef PktSession_HPP
#define PktSession_HPP

#include "../../../util/util.hpp"
#include "../FlowRule/FlowRuleManager.hpp"
#include "../ToPcaps/ToPcap.hpp"
#include <pcapplusplus/Packet.h>
#include "../Payload/PktPayload.hpp"
#include "../../LogSender/LogSender.hpp"
#include "../PacketStatus/PacketStatus.hpp"

// C 헤더 (if_indextoname)
#include <net/if.h>

// ATOMIC: 비동기 환경에서 원자적 연산을 지원하는 std::atomic을 사용하기 위해 헤더를 포함합니다.
#include <atomic>

namespace NDR
{
    namespace Sensor
    {
        namespace PacketSession
        {
            namespace Network
            {
                class NetworkSession; // NetworkSession 클래스 전방 선언

                // map:key - 네트워크 세션을 식별하기 위한 키 구조체
                struct NetworkSessionKey
                {
                    unsigned long ProtocolNumber;
                    std::string Local_IP;
                    unsigned long Local_PORT;
                    std::string Remote_IP;
                    unsigned long Remote_PORT;

                    bool operator==(const NetworkSessionKey& other) const noexcept
                    {
                        return ProtocolNumber == other.ProtocolNumber &&
                               Local_IP == other.Local_IP &&
                               Local_PORT == other.Local_PORT &&
                               Remote_IP == other.Remote_IP &&
                               Remote_PORT == other.Remote_PORT;
                    }
                };

                // map:hasher - NetworkSessionKey를 unordered_map에서 사용하기 위한 해시 함수 객체
                struct NetworkSessionKeyHash
                {
                    std::size_t operator()(const NetworkSessionKey& k) const noexcept
                    {
                        std::hash<std::string> shash;
                        return std::hash<unsigned long>()(k.ProtocolNumber) ^
                               shash(k.Local_IP) ^
                               std::hash<unsigned long>()(k.Local_PORT) ^
                               shash(k.Remote_IP) ^
                               std::hash<unsigned long>()(k.Remote_PORT);
                    }
                };

                // map:value - 각 네트워크 세션의 정보를 저장하는 구조체
                struct NetworkSessionInfo
                {
                    std::string SessionID;
                    unsigned long long first_seen_nanotimestamp;
                    
                    // ATOMIC: last_seen_nanotimestamp를 atomic으로 변경합니다.
                    // 여러 패킷 처리 스레드에서 동시에 마지막 확인 시간을 업데이트하고,
                    // 별도의 타임아웃 체크 스레드에서 이 값을 읽기 때문에 데이터 경쟁(race condition)을 방지해야 합니다.
                    std::atomic<unsigned long long> last_seen_nanotimestamp; 
                    
                    NDR::Sensor::LogSender::Logger* Logger;

                    // ATOMIC: 모든 카운터 변수를 atomic으로 변경합니다.
                    // 여러 스레드에서 동시에 패킷 카운트나 사이즈를 증감시키는 연산을 수행하므로,
                    // 락(lock) 없이 원자적으로 처리하여 성능 저하를 최소화하고 데이터 정합성을 보장합니다.
                    std::atomic<unsigned long long> egress_packet_count{0};
                    std::atomic<unsigned long long> ingress_packet_count{0};
                    std::atomic<unsigned long long> egress_packet_countCycle{0};
                    std::atomic<unsigned long long> ingress_packet_countCycle{0};
                    std::atomic<unsigned long long> PacketSize{0};
                    std::atomic<unsigned long long> PacketSizeCycle{0}; 

                    // Rulemtx는 RuleDetection과 PacketStatus 상태 변경을 동기화하기 위한 뮤텍스입니다.
                    std::shared_ptr<std::mutex> Rulemtx = nullptr;
                    std::vector<NDR::Sensor::FlowRule::RuleObjectForSession> rules;
                    std::map<std::string, unsigned long long> RulesSequenceCycleCount;

                    // PacketStatus는 복합적인 상태를 가진 객체이므로, 원자적 연산이 불가능합니다.
                    // 따라서 이 객체에 접근할 때는 Rulemtx 뮤텍스를 사용하여 스레드 안전성을 확보합니다.
                    NDR::Sensor::PacketStatus::PacketStatus PacketStatus;

                    void RuleDetection(const pcpp::Packet& PacketInstance, const NDR::Sensor::FlowRule::RuleObject::RuleDirection PktDirection)
                    {
                        // 규칙 탐지 로직 전체를 뮤텍스로 보호하여 일관성을 유지합니다.
                        std::lock_guard<std::mutex> lock(*Rulemtx);

                        if (!rules.size())
                            return;

                        for (auto& rule : rules)
                        {
                            unsigned long long DoRuleStageIndexValue = rule.currentIndex;
                            unsigned long long NextRuleStageIndexValue = DoRuleStageIndexValue;

                            // ATOMIC: atomic 변수인 last_seen_nanotimestamp 값을 읽을 때는 .load()를 사용하여 안전하게 값을 가져옵니다.
                            if (rule.Rule->Match(
                                    SessionID,
                                    PacketInstance,
                                    PktDirection,
                                    last_seen_nanotimestamp.load(std::memory_order_relaxed), // 성능을 위해 relaxed ordering 사용 가능
                                    rule.CTX,
                                    &NextRuleStageIndexValue,
                                    RulesSequenceCycleCount))
                            {
                                unsigned long long completed_stage_index;
                                if (NextRuleStageIndexValue)
                                    completed_stage_index = (NextRuleStageIndexValue - 1);
                                else
                                    completed_stage_index = DoRuleStageIndexValue;

                                auto& Stage = rule.Rule->sequence.at(completed_stage_index);

                                if (Stage.action.has_value())
                                {
                                    // 이 함수는 Rulemtx가 잠긴 상태에서 호출되므로, PacketStatus 객체와
                                    // 다른 통계 정보들을 안전하게 읽어 로그를 생성할 수 있습니다.
                                    Logger->Session_Rule_Detection_Message(
                                        SessionID,
                                        NDR::Util::timestamp::Get_Real_Timestamp(),
                                        NDR::Sensor::LogSender::SessionRuleDetectInfo{
                                            .rule_id = rule.Rule->id,
                                            .rule_description = rule.Rule->description,
                                            .severity = rule.Rule->severity,
                                            .DetectedStage = {
                                                .StageNode = completed_stage_index,
                                                .index = Stage.index,
                                                .action = {
                                                    .Action = Stage.action->type,
                                                    .message = Stage.action->message
                                                }
                                            }
                                        },
										PacketInstance,

                                        PacketStatus,

                                        // ATOMIC: 모든 atomic 변수 값을 로그에 남기기 위해 .load()로 안전하게 읽습니다.
                                        PacketSize.load(std::memory_order_relaxed),
                                        PacketSizeCycle.load(std::memory_order_relaxed),
                                        egress_packet_count.load(std::memory_order_relaxed),
                                        ingress_packet_count.load(std::memory_order_relaxed),
                                        egress_packet_countCycle.load(std::memory_order_relaxed),
                                        ingress_packet_countCycle.load(std::memory_order_relaxed)
                                    );
                                }
                            }
                            rule.currentIndex = NextRuleStageIndexValue;
                        }
                    }
                };

                class NetworkSession
                {
                public:
                    NetworkSession(
                        NDR::Sensor::LogSender::Logger& Logger,
                        NDR::Sensor::ToPcap::ToPcap& ToPcap,
                        NDR::Sensor::FlowRule::FlowRuleManager& RuleManager,
                        unsigned long long AsyncMaximumCounts = 999999
                    )
                    : Logger(Logger),
                      ToPcap(ToPcap),
                      RuleManager(RuleManager),
                      AsyncMaximumCounts(AsyncMaximumCounts)
                    {
                        network_session_check_thread = std::thread(&NetworkSession::SessionLoopChecker, this);
                        CleanupAsync = std::thread(&NetworkSession::TreeAsyncCleanUpLoopThreat_Function, this);
                    }

                    ~NetworkSession()
                    {
                        stop_thread = true;
                        if (network_session_check_thread.joinable())
                            network_session_check_thread.join();
                        if (CleanupAsync.joinable())
                            CleanupAsync.join();
                    }

                    inline bool Session_Processing(
                        unsigned long ProtocolNumber,
                        char* Local_IP, unsigned long Local_PORT,
                        char* Remote_IP, unsigned long Remote_PORT,
                        int ifindex, bool is_Ingress,
                        std::shared_ptr<pcpp::RawPacket> RawPacketInstance,
                        std::shared_ptr<pcpp::Packet> PacketInstance
                    )
                    {

                        pcpp::TcpLayer* tcp = PacketInstance->getLayerOfType<pcpp::TcpLayer>();
                        if (tcp)
                        {
                            if (Local_IP == "8.8.8.8" || Remote_IP == "8.8.8.8" || Local_PORT == 23 || Remote_PORT == 23)
                            {
                                auto* header = tcp->getTcpHeader();
                                std::cout << fmt::format("{}:{} -> {}:{} / SYN: {} ACK:{}", Local_IP, Local_PORT, Remote_IP, Remote_PORT, (unsigned long)(header->synFlag), (unsigned long)(header->ackFlag)) << std::endl;
                            }
                        }

                        NetworkSessionKey SessionKey_A = {ProtocolNumber, Local_IP, Local_PORT, Remote_IP, Remote_PORT};
                        NetworkSessionKey SessionKey_B = {ProtocolNumber, Remote_IP, Remote_PORT, Local_IP, Local_PORT};

                        // 세션 맵(Session)에 접근하는 부분은 반드시 뮤텍스로 보호해야 합니다.
                        std::lock_guard<std::mutex> lock(mtx);

                        auto it_A = Session.find(SessionKey_A);
                        auto it_B = Session.find(SessionKey_B);

                        unsigned long long nano_timestamp = NDR::Util::timestamp::Get_Real_Timestamp();
                        NDR::Sensor::FlowRule::RuleObject::RuleDirection PktDirection = is_Ingress ? NDR::Sensor::FlowRule::RuleObject::INGRESS : NDR::Sensor::FlowRule::RuleObject::EGRESS;

                        if (it_A == Session.end() && it_B == Session.end())
                        {
                            // 새로운 세션 생성
                            std::string SessionSource = Local_IP + std::to_string(Local_PORT) + Remote_IP + std::to_string(Remote_PORT) + std::to_string(nano_timestamp);
                            auto Rules = RuleManager.Get_Rules();
                            std::map<std::string, unsigned long long> RulesSequenceCycleCount;
                            for (auto& rule : Rules)
                            {
                                RulesSequenceCycleCount[rule.Rule->id] = 0;
                            }

                            auto new_session_info = std::make_shared<NetworkSessionInfo>();
                            new_session_info->SessionID = NDR::Util::hash::sha256FromString(SessionSource);
                            new_session_info->first_seen_nanotimestamp = nano_timestamp;
                            
                            // ATOMIC: atomic 변수에 초기값을 할당할 때는 .store()를 사용합니다.
                            new_session_info->last_seen_nanotimestamp.store(nano_timestamp, std::memory_order_relaxed);
                            
                            new_session_info->Logger = &Logger;
                            new_session_info->Rulemtx = std::make_shared<std::mutex>();
                            new_session_info->rules = Rules;
                            new_session_info->RulesSequenceCycleCount = RulesSequenceCycleCount;
                            
                            // ATOMIC: PacketSize는 atomic 변수이므로 .store()로 초기값을 설정합니다.
                            new_session_info->PacketSize.store(static_cast<unsigned long long>(RawPacketInstance->getRawDataLen()), std::memory_order_relaxed);

                            auto result = Session.emplace(SessionKey_A, new_session_info);
                            auto& session_ptr = result.first->second;

                            char tmp_ifname[IF_NAMESIZE];
                            const char* ifname = if_indextoname(ifindex, tmp_ifname);
                            if (ifname == nullptr) {
                                ifname = "unknown";
                            }
                            
                            bool tmp_ingress_count = 0;
                            bool tmp_egress_count = 0;
                            if(PktDirection == NDR::Sensor::FlowRule::RuleObject::RuleDirection::INGRESS)
                                tmp_ingress_count = 1;
                            else
                                tmp_egress_count = 1;

                            Logger.Session_Start_Message(
                                session_ptr->SessionID,
                                session_ptr->first_seen_nanotimestamp,
                                NDR::Sensor::LogSender::DefaultCurrentPacketInfo{
                                    .protocol = NDR::Util::ProtocolToString(ProtocolNumber),
                                    .sourceip = Local_IP,
                                    .sourceport = Local_PORT,
                                    .destinationip = Remote_IP,
                                    .destinationport = Remote_PORT,
                                    .direction = (is_Ingress ? "in" : "out"),
                                    .iface = ifname
                                },
								*PacketInstance,

                                // ATOMIC: 로그 출력을 위해 atomic 변수 값을 .load()로 읽습니다.
                                session_ptr->PacketSize.load(std::memory_order_relaxed),
                                session_ptr->PacketSizeCycle.load(std::memory_order_relaxed),

                                tmp_egress_count,
                                tmp_ingress_count
                            );

                            _post_packetsession(session_ptr, RawPacketInstance, PacketInstance, PktDirection);
                            return true;
                        }
                        else
                        {
                            // 기존 세션에 패킷 추가
                            std::shared_ptr<NetworkSessionInfo>& session_ptr = (it_A != Session.end()) ? it_A->second : it_B->second;
                            
                            // ATOMIC: last_seen_nanotimestamp 값을 업데이트할 때 .store()를 사용합니다.
                            session_ptr->last_seen_nanotimestamp.store(nano_timestamp, std::memory_order_relaxed);
                            
                            _post_packetsession(session_ptr, RawPacketInstance, PacketInstance, PktDirection);
                            return true;
                        }
                    }

                    bool EraseSession(const NetworkSessionKey& key)
                    {
                        std::lock_guard<std::mutex> lock(mtx);
                        Session.erase(key);
                        return true;
                    }

                private:
                    NDR::Sensor::LogSender::Logger& Logger;
                    NDR::Sensor::ToPcap::ToPcap& ToPcap;
                    NDR::Sensor::FlowRule::FlowRuleManager& RuleManager;

                    std::unordered_map<
                        NetworkSessionKey,
                        std::shared_ptr<NetworkSessionInfo>,
                        NetworkSessionKeyHash
                    > Session;

                    std::atomic<bool> stop_thread{false};
                    std::thread network_session_check_thread;
                    std::mutex mtx; // 세션 맵(Session) 접근을 보호하기 위한 뮤텍스
                    unsigned long long threadsleepsec = 5;
                    unsigned long long timeout = 4ULL * 1000000000; // 4초 타임아웃 범위

                    std::mutex Async_Mutex; // 비동기 작업 벡터(Async_Processing_asyncs) 접근을 보호하기 위한 뮤텍스
                    std::vector<std::future<void>> Async_Processing_asyncs;
                    std::thread CleanupAsync;
                    unsigned long long AsyncMaximumCounts;

                    void TreeAsyncCleanUpLoopThreat_Function()
                    {
                        while (!stop_thread)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100));
                            std::vector<std::future<void>> finished_tasks;
                            {
                                std::lock_guard<std::mutex> lock(Async_Mutex);
                                Async_Processing_asyncs.erase(
                                    std::remove_if(Async_Processing_asyncs.begin(), Async_Processing_asyncs.end(), 
                                        [](const std::future<void>& f) {
                                            if (!f.valid()) return true;
                                            return f.wait_for(std::chrono::seconds(0)) == std::future_status::ready;
                                        }),
                                    Async_Processing_asyncs.end()
                                );
                            }
                        }
                    }

                    inline bool _post_packetsession(
                        std::shared_ptr<NetworkSessionInfo> session_ptr,
                        std::shared_ptr<pcpp::RawPacket> RawPacketInstance,
                        std::shared_ptr<pcpp::Packet> PacketInstance,
                        NDR::Sensor::FlowRule::RuleObject::RuleDirection PktDirection
                    )
                    {
                        // LOCK: PacketStatus는 복합 객체이므로 뮤텍스로 보호하여 상태를 변경합니다.
                        // RuleDetection과 같은 뮤텍스를 공유하여 데이터 접근을 일관성 있게 관리합니다.
                        {
                            std::lock_guard<std::mutex> lock(*(session_ptr->Rulemtx));
                            session_ptr->PacketStatus.AppendPacket(*PacketInstance);
                        }

                        // ATOMIC: atomic 변수들은 '++' 연산자가 스레드 안전하게 오버로딩 되어 있어 락 없이 사용 가능합니다.
                        if( PktDirection == NDR::Sensor::FlowRule::RuleObject::RuleDirection::INGRESS )
                        {
                            if (session_ptr->ingress_packet_count.load(std::memory_order_relaxed) == 0xFFFFFFFFFFFFFFFFULL)
                            {
                                session_ptr->ingress_packet_count.store(1, std::memory_order_relaxed);
                                if (session_ptr->ingress_packet_countCycle.load(std::memory_order_relaxed) == 0xFFFFFFFFFFFFFFFFULL)
                                    session_ptr->ingress_packet_countCycle.store(1, std::memory_order_relaxed);
                                else
                                    ++session_ptr->ingress_packet_countCycle; // 원자적 증가
                            }
                            else
                                ++session_ptr->ingress_packet_count; // 원자적 증가
                        }
                        else
                        {
                            if (session_ptr->egress_packet_count.load(std::memory_order_relaxed) == 0xFFFFFFFFFFFFFFFFULL)
                            {
                                session_ptr->egress_packet_count.store(1, std::memory_order_relaxed);
                                if (session_ptr->egress_packet_countCycle.load(std::memory_order_relaxed) == 0xFFFFFFFFFFFFFFFFULL)
                                    session_ptr->egress_packet_countCycle.store(1, std::memory_order_relaxed);
                                else
                                    ++session_ptr->egress_packet_countCycle;
                            }
                            else
                                ++session_ptr->egress_packet_count;
                        }
                        
                        // ATOMIC: '+=' 연산자 또한 스레드 안전하게 오버로딩 되어 있습니다.
                        if (session_ptr->PacketSize.load(std::memory_order_relaxed) == 0xFFFFFFFFFFFFFFFFULL)
                        {
                            session_ptr->PacketSize.store(RawPacketInstance->getRawDataLen(), std::memory_order_relaxed);
                            if (session_ptr->PacketSizeCycle.load(std::memory_order_relaxed) == 0xFFFFFFFFFFFFFFFFULL)
                                session_ptr->PacketSizeCycle.store(1, std::memory_order_relaxed);
                            else
                                ++session_ptr->PacketSizeCycle;
                        }
                        else
                            session_ptr->PacketSize += RawPacketInstance->getRawDataLen(); // 원자적 덧셈

						unsigned long long size = 0;
                        {
                            std::lock_guard<std::mutex> lock(Async_Mutex);
							size = Async_Processing_asyncs.size();
                        }
						if (size >= AsyncMaximumCounts)
						{
							session_ptr->RuleDetection(*PacketInstance, PktDirection);
							return true;
						}

						{
							std::lock_guard<std::mutex> lock(Async_Mutex);
							Async_Processing_asyncs.emplace_back(
								std::async(
									std::launch::async,
									[this, session_ptr, PacketInstance, PktDirection]() mutable
									{
										session_ptr->RuleDetection(*PacketInstance, PktDirection);
									}
								)
							);
						}
                        
                        return true;
                    }

                    void SessionLoopChecker()
                    {
                        std::cout << "SessionLoopChecker working" << std::endl;
                        while (!stop_thread)
                        {
                            std::this_thread::sleep_for(std::chrono::seconds(threadsleepsec));
                            unsigned long long now_nanotimestamp = NDR::Util::timestamp::Get_Real_Timestamp();

                            {
                                std::lock_guard<std::mutex> lock(mtx);
                                for (auto it = Session.begin(); it != Session.end();)
                                {
                                    auto& session_ptr = it->second;
                                    
                                    // ATOMIC: 타임아웃을 검사하기 위해 last_seen_nanotimestamp 값을 .load()로 안전하게 읽어옵니다.
                                    if (now_nanotimestamp > (session_ptr->last_seen_nanotimestamp.load(std::memory_order_relaxed) + timeout))
                                    {
                                        // unique()는 이 세션 객체(shared_ptr)를 참조하는 곳이 현재 스레드 한 곳 뿐인지 확인합니다.
                                        // 즉, 다른 비동기 작업이 이 세션을 아직 사용하고 있지 않다는 의미입니다.
                                        if (session_ptr.unique())
                                        {
                                            std::cout << "세션종료";
                                            std::cout << session_ptr->PacketStatus.ToJson() << "\n" << std::endl;

                                            // LOCK & ATOMIC:
                                            // 타임아웃 로그를 남길 때, 다른 스레드에서 PacketStatus를 수정하는 것을 방지하고
                                            // 일관성 있는 통계 정보를 남기기 위해 Rulemtx를 잠급니다.
                                            // atomic 변수들은 .load()로 안전하게 값을 읽습니다.
                                            std::lock_guard<std::mutex> state_lock(*(session_ptr->Rulemtx));
                                            Logger.Session_Timeout_Message(
                                                session_ptr->SessionID,
                                                now_nanotimestamp,
                                                session_ptr->last_seen_nanotimestamp.load(std::memory_order_relaxed),
                                                timeout,

                                                session_ptr->PacketStatus, // Lock이 걸려있어 안전하게 접근 가능

                                                session_ptr->PacketSize.load(std::memory_order_relaxed),
                                                session_ptr->PacketSizeCycle.load(std::memory_order_relaxed),
                                                session_ptr->egress_packet_count.load(std::memory_order_relaxed),
                                                session_ptr->ingress_packet_count.load(std::memory_order_relaxed),
                                                session_ptr->egress_packet_countCycle.load(std::memory_order_relaxed),
                                                session_ptr->ingress_packet_countCycle.load(std::memory_order_relaxed)
                                            );
                                            it = Session.erase(it);
                                            std::cout << "Session timed out and erased." << std::endl;
                                        }
                                        else
                                        {
                                            // 아직 비동기 작업이 세션을 사용 중이므로, 이번 주기에는 삭제하지 않고 다음 주기로 미룹니다.
                                            ++it;
                                        }
                                    }
                                    else
                                    {
                                        ++it;
                                    }
                                }
                            }
                        }
                    }
                };
            }
        }
    }
}

#endif