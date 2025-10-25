#ifndef SENSORMANAGER_HPP
#define SENSORMANAGER_HPP

#include "../util/util.hpp"

#include "PacketFlow/PacketFlow.hpp"
#include "LogSender/LogSender.hpp"

namespace NDR
{
    namespace Sensor
    {
        class Manager
        {
            public:
                Manager(
                    NDR::Sensor::LogSender::Logger& Logger,

                    std::string FlowRuleDir, std::string PcapFileSavedDir, std::string CertsDir
                )
                : Logger(Logger),
                FlowManger(Logger, FlowRuleDir, PcapFileSavedDir, CertsDir)
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
                NDR::Sensor::LogSender::Logger& Logger;

                NDR::Sensor::PacketFlow::PacketFlowManager FlowManger;


                bool is_running = false;

        };
    }
}


#endif