#ifndef SENSORMANAGER_HPP
#define SENSORMANAGER_HPP

#include "../util/util.hpp"

#include "PacketFlow/PacketFlow.hpp"


namespace NDR
{
    namespace Sensor
    {
        class Manager
        {
            public:
                Manager(
                    std::string KafkaIp,
                    unsigned long Kafkaport,
                    std::string Kafkatopic,

                    std::string FlowRuleDir, std::string PcapFileSavedDir, std::string CertsDir
                )
                : KafkaProducer(KafkaIp, Kafkaport, Kafkatopic),
                FlowManger(KafkaProducer, FlowRuleDir, PcapFileSavedDir, CertsDir)
                {}

                ~Manager()
                {
                    this->Stop();
                }

                bool Run()
                {
                    if(is_running)
                        return false;
                    
                    
                    if( FlowManger.Run() )
                        is_running = true;
                    else
                        is_running = false;

                    return is_running;
                }

                bool Stop()
                {
                    if(!is_running)
                        return false;

                    if( FlowManger.Stop() )
                        is_running = false;
                    else
                        is_running = true;

                    return !is_running ? true : false ;
                }


            private:
                NDR::Util::Kafka::Kafka KafkaProducer;
                NDR::Sensor::PacketFlow::PacketFlowManager FlowManger;

                bool is_running = false;

        };
    }
}


#endif