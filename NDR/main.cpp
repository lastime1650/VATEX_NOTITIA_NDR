#include "Server/NDRServer.hpp"

#include "Server/APIServer/NDR_API_SERVER.hpp"

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
        "raw-ndr-sensor-linux",

        /*
            VATEX NOVA AI API Server
        */
        "192.168.1.205",
        10302,

        /*
            VATEX SAPIENTIA SIEM API Connection
        */
        "192.168.1.205",
        10900,

        /*
            VATEX INTELLINA INTELLIGENCE API Connection
        */
       "192.168.1.205",
        51034
    );
    if(!Server.Run())
        throw std::runtime_error("NDRServer Init Start Failed");
    
    
    // NDR API SERVER OPEN
    NDR::Server::API::APIServer APISvr("0.0.0.0", 30103, Server);
    APISvr.Runner();
    

    return 0;
}