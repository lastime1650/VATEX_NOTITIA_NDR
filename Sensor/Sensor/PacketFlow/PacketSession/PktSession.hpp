#ifndef PktSession_HPP
#define PktSession_HPP

#include "../../../util/util.hpp"
#include "../FlowRule/FlowRuleManager.hpp"
#include "../ToPcaps/ToPcap.hpp"
#include <pcapplusplus/Packet.h>
#include "../Payload/PktPayload.hpp"
#include "../../LogSender/LogSender.hpp"


// C 헤더 (if_indextoname)
#include <net/if.h>

namespace NDR
{
    namespace Sensor
    {
        namespace PacketSession
        {
            namespace Network
            {
                class NetworkSession; // 선언

                // map:key
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

                // map:hasher
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

                // map:value
                struct NetworkSessionInfo
                {
                    std::string SessionID;
                    unsigned long long first_seen_nanotimestamp;
                    unsigned long long last_seen_nanotimestamp;
                    NDR::Sensor::LogSender::Logger* Logger;
                    unsigned long long PacketCount = 0;
                    unsigned long long PacketCountCycle = 0;

                    std::shared_ptr<std::mutex> Rulemtx = nullptr;
                    std::vector<NDR::Sensor::FlowRule::RuleObjectForSession> rules;
                    std::map<std::string, unsigned long long> RulesSequenceCycleCount;

                    // busy_ref_count 와 사용자 정의 생성자/소멸자 모두 불필요. std::shared_ptr가 모든 것을 처리.

                    void RuleDetection(const pcpp::Packet& PacketInstance, const NDR::Sensor::FlowRule::RuleObject::RuleDirection PktDirection)
                    {
                        std::lock_guard<std::mutex> lock(*Rulemtx);

                        if (!rules.size())
                            return;

                        for (auto& rule : rules)
                        {
                            unsigned long long DoRuleStageIndexValue = rule.currentIndex;
                            unsigned long long NextRuleStageIndexValue = DoRuleStageIndexValue;

                            if (rule.Rule->Match(
                                    SessionID,
                                    PacketInstance,
                                    PktDirection,
                                    last_seen_nanotimestamp,
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
										PacketInstance
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

                        std::lock_guard<std::mutex> lock(mtx);

                        auto it_A = Session.find(SessionKey_A);
                        auto it_B = Session.find(SessionKey_B);

                        unsigned long long nano_timestamp = NDR::Util::timestamp::Get_Real_Timestamp();
                        NDR::Sensor::FlowRule::RuleObject::RuleDirection PktDirection = is_Ingress ? NDR::Sensor::FlowRule::RuleObject::INGRESS : NDR::Sensor::FlowRule::RuleObject::EGRESS;

                        if (it_A == Session.end() && it_B == Session.end())
                        {
                            std::string SessionSource = Local_IP + std::to_string(Local_PORT) + Remote_IP + std::to_string(Remote_PORT) + std::to_string(nano_timestamp);
                            auto Rules = RuleManager.Get_Rules();
                            std::map<std::string, unsigned long long> RulesSequenceCycleCount;
                            for (auto& rule : Rules)
                            {
                                RulesSequenceCycleCount[rule.Rule->id] = 0;
                            }

                            auto new_session_info = std::make_shared<NetworkSessionInfo>(
                                NetworkSessionInfo{
                                    .SessionID = NDR::Util::hash::sha256FromString(SessionSource),
                                    .first_seen_nanotimestamp = nano_timestamp,
                                    .last_seen_nanotimestamp = nano_timestamp,
                                    .Logger = &Logger,
                                    .Rulemtx = std::make_shared<std::mutex>(),
                                    .rules = Rules,
                                    .RulesSequenceCycleCount = RulesSequenceCycleCount
                                }
                            );

                            auto result = Session.emplace(SessionKey_A, new_session_info);
                            auto& session_ptr = result.first->second;

                            // FIX: 메모리 누수 해결 (new char[] -> 스택 배열)
                            char tmp_ifname[IF_NAMESIZE];
                            const char* ifname = if_indextoname(ifindex, tmp_ifname);
                            if (ifname == nullptr) {
                                // 인터페이스 이름을 찾지 못한 경우 처리
                                ifname = "unknown";
                            }
                            
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
								*PacketInstance
                            );

                            _post_packetsession(session_ptr, RawPacketInstance, PacketInstance, PktDirection);
                            return true;
                        }
                        else
                        {
                            std::shared_ptr<NetworkSessionInfo>& session_ptr = (it_A != Session.end()) ? it_A->second : it_B->second;
                            session_ptr->last_seen_nanotimestamp = nano_timestamp;
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

                    // FIX: value 타입을 std::shared_ptr로 변경
                    std::unordered_map<
                        NetworkSessionKey,
                        std::shared_ptr<NetworkSessionInfo>,
                        NetworkSessionKeyHash
                    > Session;

                    std::atomic<bool> stop_thread{false};
                    std::thread network_session_check_thread;
                    std::mutex mtx;
                    unsigned long long threadsleepsec = 5;
                    unsigned long long timeout = 4ULL * 1000000000; // 4초 타임아웃 범위

                    std::mutex Async_Mutex;
                    std::vector<std::future<void>> Async_Processing_asyncs;
                    std::thread CleanupAsync;
                    unsigned long long AsyncMaximumCounts;

                    void TreeAsyncCleanUpLoopThreat_Function()
                    {
                        while (!stop_thread)
                        {
                            std::this_thread::sleep_for(std::chrono::milliseconds(100)); // 너무 바쁘게 돌지 않도록 sleep 추가
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
                        if (session_ptr->PacketCount == 0xFFFFFFFFFFFFFFFFULL)
                        {
                            session_ptr->PacketCount = 1;
                            if (session_ptr->PacketCountCycle == 0xFFFFFFFFFFFFFFFFULL)
                                session_ptr->PacketCountCycle = 1;
                            else
                                ++session_ptr->PacketCountCycle;
                        }
                        else
                            ++session_ptr->PacketCount;

						unsigned long long size = 0;
                        {
                            std::lock_guard<std::mutex> lock(Async_Mutex);
							size = Async_Processing_asyncs.size();
                        }
						if (size >= AsyncMaximumCounts)
						{
							// FIX: 큐가 꽉 찼을 경우, 동기적으로 처리
							session_ptr->RuleDetection(*PacketInstance, PktDirection);
							return true;
						}

                        // FIX: 람다에서 shared_ptr를 값으로 캡처하여 안전하게 비동기 처리
						{
							std::lock_guard<std::mutex> lock(Async_Mutex);
							Async_Processing_asyncs.emplace_back(
								std::async(
									std::launch::async,
									[this, session_ptr, PacketInstance, PktDirection]() mutable
									{
										session_ptr->RuleDetection(*PacketInstance, PktDirection);
										// pcap 저장 로직이 필요하다면 여기에 추가
										// ToPcap.AppendPacket(...);
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
                                    if (now_nanotimestamp > (session_ptr->last_seen_nanotimestamp + timeout))
                                    {
                                        // FIX: 세션을 다른 곳(비동기 작업)에서 사용 중인지 확인
                                        // unique()는 use_count() == 1과 동일 (더 효율적일 수 있음)
                                        if (session_ptr.unique())
                                        {
                                            Logger.Session_Timeout_Message(
                                                session_ptr->SessionID,
                                                now_nanotimestamp,
                                                session_ptr->last_seen_nanotimestamp,
                                                timeout,
                                                session_ptr->PacketCount,
                                                session_ptr->PacketCountCycle
                                            );
                                            it = Session.erase(it);
                                            std::cout << "Session timed out and erased." << std::endl;
                                        }
                                        else
                                        {
                                            // 아직 비동기 작업이 세션을 사용 중. 삭제를 다음 주기로 미룸.
                                            // 디버깅 로그: std::cout << "Session timed out but is still in use (ref_count: " << session_ptr.use_count() << "), deletion postponed." << std::endl;
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