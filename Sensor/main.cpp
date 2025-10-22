#include "Sensor/SensorManager.hpp"

#include <thread>   // std::this_thread::sleep_for
#include <chrono>   // std::chrono::seconds

int main()
{
    
    NDR::Sensor::Manager Sensor(
        "192.168.1.205", 
        29092, 
        "ndr_sensor",

        "./_testrule",
        "./Pcaps",
        "./Certs"
    );
    Sensor.Run();

    std::this_thread::sleep_for(std::chrono::seconds(9999));
    
    return 0;
}