#include "Server/NDRServer.hpp"

#include <thread>   // std::this_thread::sleep_for
#include <chrono>   // std::chrono::seconds

int main()
{
    /*
        1. Kafka 기반 패킷 정보( Rule기반으로 Noise Canceling ) 수신
        2. 센서 TCP 컨트롤링
        3. Pcap 다운로드 요청 후 Raw Analyzer(자체 패킷 분석(노이즈)) ( 기획만 )
        4. SIEM 전송 (보안이벤트), 
    */
    NDR::Server::NDRServer Server(
        "192.168.1.205:29092",
        "NDR_SERVER",
        "ndr_sensor"
    );
    if(!Server.Run())
        throw std::runtime_error("NDRServer Init Start Failed");
    
    
    std::this_thread::sleep_for(std::chrono::seconds(9999));


    return 0;
}