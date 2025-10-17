#ifndef PktSession_HPP
#define PktSession_HPP

#include "../../../util/util.hpp"

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

                // NetworkSessionPtr
                class NetworkSession* parent = nullptr;  // 부모 map 접근용

                // self key for map 
                NetworkSessionKey self_key;

                // Timeout - 

                void deleteself()
                {
                    if(parent)
                        parent->EraseSession(self_key);
                }
			};

			class NetworkSession
			{
			public:
				NetworkSession()
				{
					this->network_session_check_thread = std::thread([this]() { this->SessionLoopChecker(); });
				}

				~NetworkSession()
				{
					stop_thread = true;
					if (network_session_check_thread.joinable())
						network_session_check_thread.join();
				}

				inline bool Get_NetworkSessionInfo(
					unsigned long ProtocolNumber,

					std::string Local_IP,
					unsigned long Local_PORT,

					std::string Remote_IP,
					unsigned long Remote_PORT,

					NetworkSessionInfo& output
				)
				{
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

					if (it_A == Session.end() && it_B == Session.end()) {
						NetworkSessionInfo info;

						std::string SessionSource =
							Local_IP + std::to_string(Local_PORT) +
							Remote_IP + std::to_string(Remote_PORT) +
							std::to_string(nano_timestamp);

						info.SessionID = NDR::Util::hash::sha256FromString(SessionSource);
						info.first_seen_nanotimestamp = nano_timestamp;
						info.last_seen_nanotimestamp = nano_timestamp;

                        info.self_key = SessionKey_A; // self key

						Session.emplace(SessionKey_A, info);
						output = info;
						return true;
					}
					else {
						NetworkSessionInfo& sess = (it_A != Session.end()) ? it_A->second : it_B->second;
						sess.last_seen_nanotimestamp = nano_timestamp;
						output = sess;
						return true;
					}
				}

                bool EraseSession(NetworkSessionKey key)
                {
                    Session.erase(key);
                    return true;
                }

			private:
				std::unordered_map<
					NetworkSessionKey,
					NetworkSessionInfo,
					NetworkSessionKeyHash
				> Session;

				std::atomic<bool> stop_thread{ false };
				std::thread network_session_check_thread;
				std::mutex mtx;
				unsigned long long threadsleepsec = 5;
				unsigned long long timeout = 60ULL * 1000000000;

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
								it = Session.erase(it);
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
