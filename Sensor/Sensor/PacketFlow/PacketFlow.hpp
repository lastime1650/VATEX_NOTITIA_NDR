#ifndef PacketFlowHPP
#define PacketFlowHPP

#include "../../util/util.hpp"
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>

#include "PacketReceiver/PktReceiver.hpp"
#include "PacketSession/PktSession.hpp"
#include "FlowRule/FlowRuleManager.hpp"
namespace NDR
{
    namespace Sensor
    {
        namespace PacketFlow
        {
            class PacketFlowManager
            {
            public:
                PacketFlowManager(std::string FlowRuleDir)
                : RuleManager(FlowRuleDir),
                PacketNetworkSession(RuleManager)
                {}

                ~PacketFlowManager()
                {
                    Receiver.Stop();
                }

                bool Run()
                {
                    if(is_running)
                        return false;

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
                                PacketNetworkSession.Session_Processing(
                                    PacketEvent->protocol,
                                    
                                    PacketEvent->ipSrc,
                                    PacketEvent->portSrc,
                                    PacketEvent->ipDst,
                                    PacketEvent->portDst,

                                    PacketEvent->is_INGRESS,

                                    pcppPacket
                                );

                                delete[] PktInfo.PacketEvent;
                            }
                        }
                    );

                    return true; 
                }

                bool Stop()
                {
                    return Receiver.Stop();
                }


            private:
                NDR::Sensor::PacketRecevier::Receiver Receiver; 
                NDR::Util::Queue::Queue<NDR::Util::eBPF::QueueStruct::EbpfPacketQueueStruct> PktInfoQueue;

                bool is_running = false;
                std::thread PktReceiveThread;

                NDR::Sensor::FlowRule::FlowRuleManager RuleManager;
                NDR::Sensor::PacketSession::Network::NetworkSession PacketNetworkSession;
            };
            
        }
    }
}

#endif