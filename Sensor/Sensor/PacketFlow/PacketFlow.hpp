#ifndef PacketFlowHPP
#define PacketFlowHPP

#include "../../util/util.hpp"
#include <pcapplusplus/RawPacket.h>
#include <pcapplusplus/Packet.h>

#include "PacketReceiver/PktReceiver.hpp"
namespace NDR
{
    namespace Sensor
    {
        namespace PacketFlow
        {
            class PacketFlowManager
            {
            public:
                PacketFlowManager() = default;
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
                                if(!PktInfo.RawPacket)
                                    continue;

                                if(!PktInfo.timestamp || !PktInfo.RawPacketSize)
                                {
                                    delete[] PktInfo.RawPacket;
                                    continue;
                                }

                                // 0 nano timestamp(ulong64) to timespec
                                timespec Ts;
                                NDR::Util::timestamp::Get_timespec_by_Timestamp(PktInfo.timestamp, &Ts);

                                // 1. Binary to Packet Object(but Raw!!@@$##%$@#%)
                                pcpp::RawPacket pcppRawPacket(PktInfo.RawPacket, PktInfo.RawPacketSize, Ts, false);
                                //pcppRawPacket.clone()

                                // 2. RawPacket to Packet
                                pcpp::Packet pcppPacket(&pcppRawPacket);

                                // 3. Session Processing
                                

                                delete[] PktInfo.RawPacket;
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

                

            };
            
        }
    }
}

#endif