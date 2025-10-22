#ifndef PktSession_HPP
#define PktSession_HPP



#include "../../../util/util.hpp"

#include "../FlowRule/FlowRuleManager.hpp"

#include "../ToPcaps/ToPcap.hpp"

#include <pcapplusplus/Packet.h>

#include "../Payload/PktPayload.hpp"

namespace NDR
{
    namespace Sensor
    {
		
        namespace PacketSession
        {
            namespace Network
		{
            class NetworkSession; // 선언

			// 맵 기반 네트워크 연결 관리

			// map:key
			struct NetworkSessionKey
			{
				unsigned long ProtocolNumber;

				std::string Local_IP; // 세션 생성 당시 소스 IP 
				unsigned long Local_PORT;  // 세션 생성 당시 소스 PORT

				std::string Remote_IP; // 세션 생성 당시 목적 IP 
				unsigned long Remote_PORT;  // 세션 생성 당시 목적 PORT

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
            /*
                세션에게 주어지는 CTX
            */
			struct NetworkSessionInfo
			{
				std::string SessionID;
				unsigned long long first_seen_nanotimestamp;
				unsigned long long last_seen_nanotimestamp;

				// To Pcap
				NDR::Sensor::ToPcap::ToPcap ToPcapFileSaver;


                unsigned long long PacketCount = 0;
                unsigned long long PacketCountCycle = 0; // unsigned long long 범위 초과시 ++1 

				// 

                // Timeout - 

                // 규칙기반 Flow 감지 (  )
                std::vector< NDR::Sensor::FlowRule::RuleObjectForSession > rules;
				std::map<std::string,unsigned long long> RulesSequenceCycleCount; // 특정 rule의 시퀀스 전체 회전 카운트 최소1 이상값이 들어가면 "전체 성공"으로 취급.
                void RuleDetection(const pcpp::Packet& PacketInstance, const NDR::Sensor::FlowRule::RuleObject::RuleDirection PktDirection)
                {
                    if( !rules.size() )
                        return;
                    
                    for(auto& rule : rules)
                        rule.Rule->Match(
                            // Live Data - From Session Execlusive Node
                            PacketInstance, 
                            PktDirection, 
                            

                            // Stored Data - From Session Execlusive Node
                            rule.CTX,
                            &rule.currentIndex,
							RulesSequenceCycleCount
                        );
                }

                // 바이너리 등 상위 프로토콜 검사
                //void DPI(pcpp::Packet& PacketInstance)
                //{
                    
                //}
			};

			class NetworkSession
			{
			public:
				NetworkSession(std::string PcapSavedDir, NDR::Sensor::FlowRule::FlowRuleManager& RuleManager)
                : RuleManager(RuleManager),
				PcapSavedDir(PcapSavedDir)
				{
					this->network_session_check_thread = std::thread(
                        [this]() { 
                            this->SessionLoopChecker(); 
                        }
                    );
				}

				~NetworkSession()
				{
					stop_thread = true;
					if (network_session_check_thread.joinable())
						network_session_check_thread.join();
				}


				inline bool Session_Processing(
					unsigned long ProtocolNumber,

					std::string Local_IP,
					unsigned long Local_PORT,

					std::string Remote_IP,
					unsigned long Remote_PORT,

                    bool is_Ingress,

                    pcpp::RawPacket& RawPacketInstance,
					pcpp::Packet& PacketInstance
				)
				{
                    pcpp::TcpLayer* tcp = PacketInstance.getLayerOfType<pcpp::TcpLayer>();
                    if( tcp )
                    {
                        if (Local_IP == "8.8.8.8" || Remote_IP == "8.8.8.8")
                        {
                            auto* header = tcp->getTcpHeader();
                            std::cout << fmt::format("{}:{} -> {}:{} / SYN: {} ACK:{}", Local_IP, Local_PORT, Remote_IP, Remote_PORT, (unsigned long)(header->synFlag), (unsigned long)(header->ackFlag)) << std::endl;
                        
                        }
                    }
                    

					NetworkSessionKey SessionKey_A; // 정방향 키
					NetworkSessionKey SessionKey_B; // 역방향 키

					SessionKey_A.ProtocolNumber = ProtocolNumber;
					SessionKey_A.Local_IP = Local_IP;
					SessionKey_A.Local_PORT = Local_PORT;
					SessionKey_A.Remote_IP = Remote_IP;
					SessionKey_A.Remote_PORT = Remote_PORT;

					SessionKey_B.ProtocolNumber = ProtocolNumber;
					SessionKey_B.Local_IP = Remote_IP;
					SessionKey_B.Local_PORT = Remote_PORT;
					SessionKey_B.Remote_IP = Local_IP;
					SessionKey_B.Remote_PORT = Local_PORT;

					std::lock_guard<std::mutex> lock(mtx);

					auto it_A = Session.find(SessionKey_A);
					auto it_B = Session.find(SessionKey_B);

					unsigned long long nano_timestamp = NDR::Util::timestamp::Get_Real_Timestamp();

                    NDR::Sensor::FlowRule::RuleObject::RuleDirection PktDirection = is_Ingress ? NDR::Sensor::FlowRule::RuleObject::INGRESS : NDR::Sensor::FlowRule::RuleObject::EGRESS; 

					if (it_A == Session.end() && it_B == Session.end()) {

						std::string SessionSource =
							Local_IP + std::to_string(Local_PORT) +
							Remote_IP + std::to_string(Remote_PORT) +
							std::to_string(nano_timestamp);


						auto Rules = RuleManager.Get_Rules();

						std::map<
							std::string,
							unsigned long long
						> RulesSequenceCycleCount;

						for (auto& rule : Rules)
						{
							RulesSequenceCycleCount[rule.Rule->id] = 0;
						}

                        Session.emplace(
                            SessionKey_A, 
                            NetworkSessionInfo{

                                .SessionID = NDR::Util::hash::sha256FromString(SessionSource),
                                .first_seen_nanotimestamp = nano_timestamp,
                                .last_seen_nanotimestamp = nano_timestamp,
                                
                                .rules = Rules,
								.RulesSequenceCycleCount = RulesSequenceCycleCount
                            }
                        );

						// Enable ToPcap Instance
						Session[SessionKey_A].ToPcapFileSaver.Initialize(
							PcapSavedDir,
							Session[SessionKey_A].SessionID,
							Session[SessionKey_A].first_seen_nanotimestamp
						);
						Session[SessionKey_A].ToPcapFileSaver.Run();

                        /*
                            Postfix 작업
                        */
                        _post_packetsession(Session[SessionKey_A], RawPacketInstance, PacketInstance, PktDirection);
                        //std::cout << "session 생성된 - "  << info.PacketCount<< std::endl;
						return true;
					}
					else {
						NetworkSessionInfo& sess = (it_A != Session.end()) ? it_A->second : it_B->second;
						sess.last_seen_nanotimestamp = nano_timestamp;

                        /*
                            Postfix 작업
                        */
                        _post_packetsession(sess, RawPacketInstance, PacketInstance, PktDirection);
                        //std::cout << "session 유지중 - " << sess.PacketCount << std::endl;
						return true;
					}
				}

                bool EraseSession(NetworkSessionKey key)
                {
                    Session.erase(key);
                    return true;
                }

			private:
				std::string PcapSavedDir;
                NDR::Sensor::FlowRule::FlowRuleManager& RuleManager;

				std::unordered_map<
					NetworkSessionKey,
					NetworkSessionInfo,
					NetworkSessionKeyHash
				> Session;

				std::atomic<bool> stop_thread{ false };
				std::thread network_session_check_thread;
				std::mutex mtx;
				unsigned long long threadsleepsec = 5;
				unsigned long long timeout = 10ULL * 1000000000; // 10초 타임아웃 범위

                // Postfix Function
                inline bool _post_packetsession( NetworkSessionInfo& session, pcpp::RawPacket& RawPacketInstance, pcpp::Packet& PacketInstance, NDR::Sensor::FlowRule::RuleObject::RuleDirection PktDirection )
                {
                    // 0. 패킷 카운트 증가
                    if(session.PacketCount == (unsigned long long )0xFFFFFFFFFFFFFFFF)
                    {
                        session.PacketCount = 1;
                        ++session.PacketCountCycle;
                    }
                    else
                        ++session.PacketCount;

						
					// 1. pcap 파일 저장 ( 무조건 비동기 처리여야함 )
					session.ToPcapFileSaver.AppendPacket(
						session.last_seen_nanotimestamp, // 해당 패킷 최근 발생시간 ( 최신 )

						RawPacketInstance.getRawData(),
						RawPacketInstance.getRawDataLen()
					);

                    // 2. session이 독자적으로 가지고 있는 규칙/정책을 진행
                    session.RuleDetection( PacketInstance, PktDirection );

					// 3. 
					
                }

				void SessionLoopChecker()
				{
					while (!stop_thread)
					{
						std::this_thread::sleep_for(std::chrono::seconds(threadsleepsec));

						unsigned long long now_nanotimestamp = NDR::Util::timestamp::Get_Real_Timestamp();

						std::lock_guard<std::mutex> lock(mtx);

						for (auto it = Session.begin(); it != Session.end(); )
						{
							NetworkSessionInfo& value = it->second;

							if (now_nanotimestamp > (value.last_seen_nanotimestamp + timeout))
								{
                                    it = Session.erase(it);
                                    //std::cout << "timeout! || " << fmt::format("{}:{} -> {}:{}", value.self_key.Local_IP, value.self_key.Local_PORT, value.self_key.Remote_IP, value.self_key.Remote_PORT) << std::endl;
                                }
							else
								++it;
						}
					}
				}
			};
		}
        }
    }
}

#endif
