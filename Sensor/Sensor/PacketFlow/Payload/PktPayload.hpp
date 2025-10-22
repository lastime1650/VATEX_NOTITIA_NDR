#ifndef PACKET_PAYLOAD_HPP
#define PACKET_PAYLOAD_HPP

#include "../../../util/util.hpp"
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>

#include <pcapplusplus/TcpReassembly.h>

namespace NDR
{
    namespace Sensor
    {
        namespace PacketPayload
        {
             
            class PacketPayloadBase
            {
                public:
                    PacketPayloadBase() = default;
                    virtual ~PacketPayloadBase() = default;

                    // Get Payload
                    void Payload(  pcpp::Packet& pkt, uint8_t* payload,  unsigned long payload_len )
                    {
                        // 0. check valid
                        if(!payload || !payload_len)
                            return;

                        // 1. Payload 분석 ( default )
                        std::thread(
                            [this, PacketPayloadBuffer = std::vector<uint8_t>(payload, payload + payload_len)]()
                            {

                            }  
                        ).detach();

                        // 2. 분석 결과에 대한 NDR 전송
                    }

                private:
                    
                    
            };

            class ConnectedProtocol
            {
                public:
                    ConnectedProtocol(std::string SessionId)
                    :
                    SessionId(SessionId),
                    TR(this->OnTcpMessageReady, this)
                    {
                        
                    }
                    ~ConnectedProtocol() = default;

                    void Payload(  pcpp::Packet& pkt )
                    {
                        TR.reassemblePacket(pkt.getRawPacket());
                    }

                private:
                    std::string SessionId;
                    std::vector<uint8_t> Buffer;

                    pcpp::TcpReassembly TR;
                    // (*OnTcpMessageReady)(int8_t side, const TcpStreamData& tcpData, void* userCookie);
                    static void OnTcpMessageReady(int8_t side, const pcpp::TcpStreamData& tcpData, void* userCookie)
                    {
                        ConnectedProtocol* Instance = (ConnectedProtocol*)userCookie;

                        if(tcpData.getDataLength())
                        {
                            std::cout << "PKT SIZE : " << tcpData.getDataLength();
                        }

                    }
            };

            class Non_ConnectedProtocol
            {

            };

            class PacketPayloadManager
            {
                public:
                    PacketPayloadManager( pcpp::Packet& Pkt )
                    {

                    }

                private:
            };
        }
    }
}

#endif