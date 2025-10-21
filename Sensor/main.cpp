#include "Sensor/SensorManager.hpp"

#include <thread>   // std::this_thread::sleep_for
#include <chrono>   // std::chrono::seconds

#include "Sensor/PacketFlow/Ssl/Ssl.hpp"

int main()
{
    /*
    NDR::Sensor::Manager Sensor(
        //"./FlowRules"
        "./_testrule",
        "./Pcaps"
    );
    Sensor.Run();*/
    NDR::Sensor::SSL::SSL_Manager test(
        "./Certs"
    );


    std::this_thread::sleep_for(std::chrono::seconds(9999));

    return 0;
}