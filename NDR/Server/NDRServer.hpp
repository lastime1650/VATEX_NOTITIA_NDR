#ifndef NDR_SERVER_HPP
#define NDR_SERVER_HPP

#include "../Util/util.hpp"

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
                    std::string topic
                )
                : Kafka(BrokerConnection, groupid, topic),
                SessionTracker(Kafka)
                {

                }
                ~NDRServer(){Stop();}

                bool Run()
                {
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
        };
    }
}

#endif