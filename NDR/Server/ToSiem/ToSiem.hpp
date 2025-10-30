#ifndef TOSIEM_HPP
#define TOSIEM_HPP

#include "../../Util/util.hpp"
#include <iomanip>

namespace NDR
{
    namespace Server
    {
        namespace ToSiemGlobal
        {
            namespace Platform
            {
                constexpr char* Platform  = "ndr";
            }
            namespace Topic
            {
                constexpr char* Network_Tcp  = "network-tcp";
            }
            namespace Severity
            {
                constexpr char* Notice  = "notice";
                constexpr char* Low  = "low";
                constexpr char* Medium  = "medium";
                constexpr char* High  = "high";
                constexpr char* Critical  = "critical";
            }
            namespace EventId
            {
                // <platform>-<category>-<numeric_id>
                // ex) ndr-tcp-00000001
                class EventId
                {
                    public:
                        EventId(std::string Platform, std::string EventCategory, unsigned long EventNumber)
                        {
                            /*
                                부호없는 4바이트 값을 다음과 같은 형태로 저장
                                -> "000000001"
                            */
                            std::ostringstream oss;
                            oss << std::setw(10) << std::setfill('0') << EventNumber;
                            std::string EventNumberStr = oss.str();


                            eventid = Platform  + "-" + EventCategory + "-" + EventNumberStr;
                        }
                        ~EventId() = default;

                        std::string Get_EventId()
                        {
                            return eventid;
                        }

                    private:
                        std::string eventid;
                    
                };
            }

        }

        class ToSiem
        {
            public:
                ToSiem(
                    std::string Elasticsearch_Connection_Url = "http://localhost:9200"

                )
                : Elasticsearch_Connection_Url(Elasticsearch_Connection_Url)
                {}

            private:
                std::string Elasticsearch_Connection_Url;
        };
    }
}


#endif