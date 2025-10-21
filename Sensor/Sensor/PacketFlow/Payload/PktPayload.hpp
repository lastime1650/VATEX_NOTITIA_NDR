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
                    ConnectedProtocol(std::string SessionId):SessionId(SessionId){}
                    ~ConnectedProtocol() = default;

                    void Payload(  pcpp::Packet& pkt )
                    {
                        pcpp::TcpLayer* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
                        if(!tcp)
                            return;

                        uint8_t* payload = tcp->getLayerPayload();
                        unsigned long payload_len = tcp->getLayerPayloadSize();

                        if (payload_len == 0)
                            return; // ACK-only packet → skip
                        
                        if( 
                            !_reassemble_tracking( 
                                (long long)tcp->getTcpHeader()->ackNumber, 
                                (long long)tcp->getTcpHeader()->sequenceNumber, 
                                payload, 
                                payload_len
                            )
                        )
                        {
                            
                            // 리어셈블 패킷이 아닐 때, 개별 패킷 페이로드 분석으로 진행할 수 있다.
                            /* ...*/
                        }
                        else
                        {
                            std::cout <<"SESSION: " << SessionId << "  | 리어셈블리 패킷";
                        }
                    }

                private:
                    std::string SessionId;
                    std::vector<uint8_t> Buffer;
                    long long previous_Ack_Num = -1;
                    long long previous_Seq_Num = -1;
                
                    enum Fixed_Number_type
                    {
                        none,
                        Seq,
                        Ack
                    };
                    Fixed_Number_type FixedType = none;

                    // return:
                    //   true  -> 리어셈블 중 (Buffer에 누적됨)
                    //   false -> 새 스트림 or 리어셈블 종료
                    bool _reassemble_tracking(long long current_Ack_Num, long long current_Seq_Num,
                                            uint8_t* payload, unsigned long payload_len)
                    {
                        // 첫 패킷 초기화
                        if (previous_Ack_Num == -1 && previous_Seq_Num == -1)
                        {
                            previous_Ack_Num = current_Ack_Num;
                            previous_Seq_Num = current_Seq_Num;
                            Buffer.insert(Buffer.end(), payload, payload + payload_len);
                            return false;
                        }

                        switch (FixedType)
                        {
                        case Seq:
                        {
                            if (previous_Seq_Num == current_Seq_Num)
                            {
                                // 동일 송신자의 리어셈블 패킷 (연속 segment)
                                Buffer.insert(Buffer.end(), payload, payload + payload_len);
                                // 다음 비교 대비 상태 갱신
                                previous_Ack_Num = current_Ack_Num;
                                previous_Seq_Num = current_Seq_Num;
                                return true;
                            }
                            else
                            {
                                // 송신자가 리어셈블 스트림 종료
                                /* 지금까지 Buffer 처리 */
                                Buffer.clear();
                                FixedType = none;

                                // 다음 세션 초기화
                                previous_Ack_Num = current_Ack_Num;
                                previous_Seq_Num = current_Seq_Num;
                                Buffer.insert(Buffer.end(), payload, payload + payload_len);
                                return false;
                            }
                        }

                        case Ack:
                        {
                            if (previous_Ack_Num == current_Ack_Num)
                            {
                                // 동일 Ack 유지 → 리어셈블 중
                                Buffer.insert(Buffer.end(), payload, payload + payload_len);
                                previous_Ack_Num = current_Ack_Num;
                                previous_Seq_Num = current_Seq_Num;
                                return true;
                            }
                            else
                            {
                                // Ack 변화 → 새로운 스트림으로 판단
                                /* 지금까지 Buffer 처리 */
                                Buffer.clear();
                                FixedType = none;

                                previous_Ack_Num = current_Ack_Num;
                                previous_Seq_Num = current_Seq_Num;
                                Buffer.insert(Buffer.end(), payload, payload + payload_len);
                                return false;
                            }
                        }

                        case none:
                        {
                            // 아직 리어셈블 송신자 미확정 → Ack 또는 Seq 고정자 찾기
                            if (previous_Ack_Num == current_Ack_Num)
                            {
                                FixedType = Ack;
                                Buffer.insert(Buffer.end(), payload, payload + payload_len);
                                previous_Ack_Num = current_Ack_Num;
                                previous_Seq_Num = current_Seq_Num;
                                return true;
                            }
                            else if (previous_Seq_Num == current_Seq_Num)
                            {
                                FixedType = Seq;
                                Buffer.insert(Buffer.end(), payload, payload + payload_len);
                                previous_Ack_Num = current_Ack_Num;
                                previous_Seq_Num = current_Seq_Num;
                                return true;
                            }
                            else
                            {
                                // 리어셈블 패턴 불명 → 새로운 흐름으로 초기화
                                Buffer.clear();
                                previous_Ack_Num = current_Ack_Num;
                                previous_Seq_Num = current_Seq_Num;
                                Buffer.insert(Buffer.end(), payload, payload + payload_len);
                                return false;
                            }
                        }
                        }

                        return false; // default safety
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