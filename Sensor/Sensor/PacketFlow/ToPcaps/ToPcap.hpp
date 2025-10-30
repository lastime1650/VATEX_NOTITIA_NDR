    #ifndef ToPCAP_HPP
    #define ToPCAP_HPP

    #include "../../../util/util.hpp"

    namespace NDR
    {
        namespace Sensor
        {
            namespace ToPcap
            {

                struct pcap_file_header {
                    uint32_t magic_number = 0xa1b2c3d4;  // 표준 매직넘버
                    uint16_t version_major = 2;          // 보통 2
                    uint16_t version_minor = 4;          // 보통 4
                    int32_t  thiszone = 0;               // GMT 기준 오프셋
                    uint32_t sigfigs = 0;                // 정확도 (사용 안함)
                    uint32_t snaplen = 65535;            // 최대 캡처 길이
                    uint32_t network = 1;                // 링크타입 (1 = Ethernet)
                };

                struct pcap_pkthdr {
                    uint32_t ts_sec;   // 초 단위 타임스탬프
                    uint32_t ts_usec;  // 마이크로초 단위 (ns를 us로 변환)
                    uint32_t incl_len; // 저장된 길이
                    uint32_t orig_len; // 실제 길이
                };

                struct ToPcapQueueData
                {
                    std::string SessionId;

                    unsigned long long timestamp;
                    std::vector<uint8_t> Frame;
                };

                // PacketSession별로 아래 ToPcap 클래스를 가진다. 
                class ToPcap
                {
                    

                    public:
                        ToPcap(std::string PcapDir):PcapDir(PcapDir){}
                        ~ToPcap(){
                            std::cout << "~ToPcap called" << std::endl;
                            Stop();
                            std::cout << "~ToPcap end" << std::endl;
                        }

                        bool save_pcap( std::string SessionId, unsigned long long Timestamp, pcap_pkthdr* pkthdr, const uint8_t* PacketData, const uint8_t* PacketDataEnd ) 
                        {
                            // Make PcapFileName (abs PATH)
                            /*
                                Example)
                                    -> ./Pcaps/MyFlowPacketSessionA2352-1290423533.pcap
                            */
                            if(PcapDir.back() == '/')
                                PcapDir.pop_back();

                            auto TimestampStr = std::to_string(Timestamp);

                            std::string pcapFileFullPath;
                            pcapFileFullPath.reserve(
                                PcapDir.size() + SessionId.size() + TimestampStr.size() + 7 + 1
                            );
                            pcapFileFullPath = ( PcapDir + "/" + SessionId + "-" + TimestampStr + ".pcap" );

                            // 최초 패킷 저장인가?
                            if( !this->FileHandlerInstance.is_valid_file(pcapFileFullPath) )
                            {
                                // 최초일 때,
                                // PCAP 파일 시그니처 입력
                                this->FileHandlerInstance.writeToFile(
                                    pcapFileFullPath,
                                    std::vector<uint8_t>( (uint8_t*)&global_header, ( ( (uint8_t*)&global_header )+ sizeof(global_header) ) )
                                );
                            }

                            // 패킷 저장
                            this->FileHandlerInstance.writeToFile(
                                                pcapFileFullPath,
                                                std::vector<uint8_t>( (uint8_t*)pkthdr, ( (uint8_t*)pkthdr + sizeof(pcap_pkthdr) )  ),
                                                true
                                            );

                            this->FileHandlerInstance.writeToFile(
                                                pcapFileFullPath,
                                                std::vector<uint8_t>( PacketData, PacketDataEnd ),
                                                true
                                            );
                            

                            return true;

                        }

                        bool Run()
                        {
                            if(is_running)
                                return false;
                            
                            is_running = true;

                            ToPcapLoopThread = std::thread(
                                [this]()
                                {
                                    while(this->is_running)
                                    {
                                        auto FramePacketInfo = this->ToPcapQueue.get();

                                        {
                                            /*
                                                1. Pcap 패킷 헤더 추가
                                            */
                                            pcap_pkthdr pkthdr;
                                            pkthdr.ts_sec   = FramePacketInfo.timestamp / 1000000000ULL;
                                            pkthdr.ts_usec  = (FramePacketInfo.timestamp % 1000000000ULL) / 1000;
                                            pkthdr.incl_len = FramePacketInfo.Frame.size();
                                            pkthdr.orig_len = FramePacketInfo.Frame.size();

                                            /*
                                                2. 패킷 바이너리 이어서.
                                            */
                                            const uint8_t* PacketData = FramePacketInfo.Frame.data();
                                            const uint8_t* PacketDataEnd = PacketData + FramePacketInfo.Frame.size();

                                            this->save_pcap(
                                                FramePacketInfo.SessionId,
                                                FramePacketInfo.timestamp,
                                                &pkthdr,
                                                PacketData,
                                                PacketDataEnd
                                            );
                                        }
                                    }
                                    

                                }
                            );

                            return true;
                        }
                        bool Stop()
                        {
                            if(!is_running)
                                return false;

                            is_running = false;

                            if(ToPcapLoopThread.joinable())
                                ToPcapLoopThread.join();
                            
                                
                            return true;
                        }

                        bool AppendPacket( std::string flow_session_id, unsigned long long timestamp, const uint8_t* RealPacketDataPtr, const size_t PacketDataLen )
                        {
                            if(PacketDataLen && RealPacketDataPtr)
                            {
                                ToPcapQueue.put(
                                    ToPcapQueueData{
                                        .SessionId = flow_session_id,
                                        .timestamp = timestamp,
                                        .Frame = std::vector<uint8_t>(RealPacketDataPtr, RealPacketDataPtr+PacketDataLen)
                                    }
                                );
                            }
                        }

                    private:
                        pcap_file_header global_header;
                        NDR::Util::File::FileHandler FileHandlerInstance;

                        bool is_running = false;
                        std::thread ToPcapLoopThread;

                        NDR::Util::Queue::Queue<ToPcapQueueData> ToPcapQueue;
                        std::string PcapDir;

                };
            }
        }
    }



    #endif