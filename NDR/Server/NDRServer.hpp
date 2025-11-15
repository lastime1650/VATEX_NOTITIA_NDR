#ifndef NDR_SERVER_HPP
#define NDR_SERVER_HPP

#include "../Util/util.hpp"
#include "AIMananger/AIManager.hpp"

#include "FlowSessionTracker/FlowSessionTracker.hpp"

namespace NDR
{
    namespace Server
    {
        class NDRServer{
            public:
            /*
                <생성자> 
                1. KAFKA 인스턴스
            */
                NDRServer(
                    std::string BrokerConnection,
                    std::string groupid,
                    std::string topic,


                    std::string VATEX_NOVA_AI_API_ServerIp,
                    unsigned int VATEX_NOVA_AI_API_ServerPort,

                    std::string VATEX_SAPIENTIA_SIEM_API_ServerIp,
                    unsigned int VATEX_SAPIENTIA_SIEM_API_ServerPort,

                    std::string VATEX_INTELLINA_API_ServerIp,
                    unsigned int VATEX_INTELLINA_API_ServerPort = 51034
                )
                : Kafka(BrokerConnection, groupid, topic),

                SiemClient(VATEX_SAPIENTIA_SIEM_API_ServerIp, VATEX_SAPIENTIA_SIEM_API_ServerPort),
                IntelligenceManager(VATEX_INTELLINA_API_ServerIp, VATEX_INTELLINA_API_ServerPort),
                AIManager(VATEX_NOVA_AI_API_ServerIp, VATEX_NOVA_AI_API_ServerPort, SiemClient),


                SessionTracker(Kafka, AIManager, IntelligenceManager, SiemClient)
                {

                }
                ~NDRServer(){Stop();}

                bool Run()
                {
                    std::cout << "Run";
                    if(is_running)
                        return false;

                    if( !Kafka.Run() )
                        throw std::runtime_error("KAFKA INIT RUN FAILED");
                    
                    if( !SessionTracker.Run() )
                         throw std::runtime_error("SessionTracker INIT RUN FAILED");

                    is_running = true;
                    return true;
                }
                bool Stop()
                {
                    if(!is_running)
                        return false;

                    Kafka.Stop();

                    return true;
                }
                
            private:
                bool is_running = false;
                NDR::Util::Kafka::Kafka_Consumer Kafka;
                NDR::Server::SessionTracking::SessionTracker SessionTracker;




                NDR::Util::ToSiem::SiemClient SiemClient;
                NDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE IntelligenceManager;
                NDR::AI::AI_MANAGER AIManager;
        };
    }
}

#endif