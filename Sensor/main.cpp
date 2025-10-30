#include "Sensor/SensorManager.hpp"

#include "util/util.hpp"

#include <thread>   // std::this_thread::sleep_for
#include <chrono>   // std::chrono::seconds

#include "Sensor/LogSender/LogSender.hpp"
int main()
{
    // 1. Sensor Device ID
    std::string Sensor_ID = NDR::Util::hardware::Get_Hardware_hash();
    // 2. Logger Instance
    NDR::Sensor::LogSender::Logger Logger(
        Sensor_ID,
        "192.168.1.205", 
        29092, 
        "ndr_sensor"
    );
    


    NDR::Sensor::Manager Sensor(
        Logger,

        "./FlowRules",
        "./Pcaps",
        "./Certs"
    );
    Sensor.Run();

    std::this_thread::sleep_for(std::chrono::seconds(9999));
    
    return 0;
}