#ifndef PacketFlowHPP
#define PacketFlowHPP

#include "../../util/util.hpp"
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>

#include "PacketReceiver/PktReceiver.hpp"
#include "PacketSession/PktSession.hpp"
#include "FlowRule/FlowRuleManager.hpp"
#include "Ssl/Ssl.hpp"

#include "../LogSender/LogSender.hpp"

namespace NDR
{
    namespace Sensor
    {
        namespace PacketFlow
        {
            class PacketFlowManager
            {
            public:
                PacketFlowManager(NDR::Sensor::LogSender::Logger& Logger, std::string FlowRuleDir, std::string PcapSavedDir, std::string CertsDir)
                : Logger(Logger),
                ToPcap(PcapSavedDir),
                RuleManager(Logger, FlowRuleDir),
                SSL_Manager(CertsDir),
                PacketNetworkSession(Logger, ToPcap, RuleManager)
                {}

                ~PacketFlowManager()
                {
                    Receiver.Stop();
                }

                bool Run()
                {
                    if(is_running)
                        return false;
                    
                    if(!ToPcap.Run() )
                        return false;
                    
                    // SSL Proxy Open
                    if( !SSL_Manager.Run() )
                        return false;

                    // Ebpf Packet Receive Open
                    if( !Receiver.Run( &PktInfoQueue) ) // 큐 객체 관리는 오로지 "PacketFlowManager" 에서 담당 
                        return false;

                    // Packet Loop Receiver
                    is_running = true;
                    PktReceiveThread = std::thread(
                        [this]()
                        {
                            while(this->is_running)
                            {
                                auto PktInfo = this->PktInfoQueue.get();
                                //std::cout << PktInfo.timestamp << std::endl;
                                if(!PktInfo.PacketEvent)
                                    continue;

                                if(!PktInfo.timestamp || !PktInfo.RawPacketSize)
                                {
                                    delete[] PktInfo.PacketEvent;
                                    continue;
                                }
                                
                                // casting
                                auto* PacketEvent = (NDR::Util::eBPF::Network_event*)PktInfo.PacketEvent;
                                // 0 nano timestamp(ulong64) to timespec
                                timespec Ts;
                                NDR::Util::timestamp::Get_timespec_by_Timestamp(PktInfo.timestamp, &Ts);

                                // 1. Binary to Packet Object(but Raw!!@@$##%$@#%)
                                pcpp::RawPacket pcppRawPacket(PacketEvent->RawPacket, PktInfo.RawPacketSize, Ts, false);
                                //pcppRawPacket.clone()

                                // 2. RawPacket to Packet
                                pcpp::Packet pcppPacket(&pcppRawPacket);

                                // 3. Session Processing
                                //std::cout << "Session_Processing .." << std::endl;
                                PacketNetworkSession.Session_Processing(
                                    PacketEvent->protocol,
                                    
                                    PacketEvent->ipSrc,
                                    PacketEvent->portSrc,
                                    PacketEvent->ipDst,
                                    PacketEvent->portDst,

                                    PacketEvent->ifindex,
                                    PacketEvent->is_INGRESS,

                                    pcppRawPacket,
                                    pcppPacket
                                );
                                //td::cout << "Session_Processing END" << std::endl;

                                delete[] PktInfo.PacketEvent;
                            }
                            std::cout << "탈출된";
                            while(!this->PktInfoQueue.empty())
                            {
                                delete[] this->PktInfoQueue.get().PacketEvent;
                            }
                        }
                    );

                    return true; 
                }

                bool Stop()
                {
                    if(!is_running)
                        return false;

                    if( !ToPcap.Stop() )
                        return false;

                    // Ebpf Receive Closing
                    if( !Receiver.Stop() )
                        return false;

                    // SSL Proxy Closing
                    if( !SSL_Manager.Stop() )
                        return false;

                    is_running = false;
                    return true;
                }


            private:
                NDR::Sensor::SSL::SSL_Manager SSL_Manager;
                NDR::Sensor::PacketRecevier::Receiver Receiver; 
                NDR::Sensor::ToPcap::ToPcap ToPcap;


                NDR::Util::Queue::Queue<NDR::Util::eBPF::QueueStruct::EbpfPacketQueueStruct> PktInfoQueue;

                bool is_running = false;
                std::thread PktReceiveThread;

                NDR::Sensor::FlowRule::FlowRuleManager RuleManager;
                NDR::Sensor::PacketSession::Network::NetworkSession PacketNetworkSession;


                NDR::Sensor::LogSender::Logger& Logger;
            };
            
        }
    }
}

#endif