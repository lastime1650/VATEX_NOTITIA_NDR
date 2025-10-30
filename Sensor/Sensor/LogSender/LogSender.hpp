#ifndef LOGSENDER_HPP
#define LOGSENDER_HPP

#include "../../util/util.hpp"

namespace NDR
{
    namespace Sensor
    {
        namespace LogSender
        {
            struct DefaultCurrentPacketInfo
            {
                // 현재 패킷 정보 (단일)
                std::string protocol;
                        
                std::string sourceip;
                unsigned long sourceport;

                std::string destinationip;
                unsigned long destinationport;

                std::string direction;
                std::string iface;

            };

            struct SessionPacketInfo
            {
                // 현재 세션에 포함된 세션 정보 (복수)
                // * Flow_Session_Id를 통해서 사전에 {DefaultCurrentPacketInfo} 값을 NDR단에서 찾아 연계해야함
                unsigned long long PktCount;
                unsigned long long CycleAllPktCount;

                unsigned long long SessionStartTimestamp;
                unsigned long long SessionCurrentTimestamp;
                
            };

            struct SessionRuleDetectInfo
            {
                std::string rule_id;
                std::string rule_description;
                std::string severity;
                struct
                {
                    unsigned long long StageNode;
                    std::string index;

                    struct
                    {
                        std::string Action;
                        std::string message;
                    }action;

                }DetectedStage;
            };

            constexpr const char* SessionStart = "session_start";
            constexpr const char* SessionRule = "session_rule";
            constexpr const char* SessionTimeout = "session_timeout";
            //constexpr const char* SessionEnd = "SessionEnd";

            class Logger
            {
                public:
                    Logger(
                        std::string sensor_id,


                        std::string KafkaIp,
                        unsigned long Kafkaport,
                        std::string Kafkatopic
                    ):
                    sensor_id(sensor_id),
                    KAFKA(KafkaIp, Kafkaport, Kafkatopic)
                    {
                        if (!this->KAFKA.Initialize() )
                            throw std::runtime_error("Kafka init Connect Failed");
                    }
                    ~Logger(){}

                    //1. Session Start
                    bool Session_Start_Message(
                        std::string Flow_Session_Id,
                        unsigned long long NanoTimestamp,

                        const DefaultCurrentPacketInfo& CurrentPktInfo
                    )
                    {
                        /*

                        {
                            "header": {
                                "sensor_id": "sha256",
                                "flow_session_id": "sha256",
                                "nano_timestamp": 0000
                            },
                            "body": {}
                        }
                        */
                        // 세션 시작
                        KAFKA.InsertMessage(
                            {
                                {"header",{
                                    {"sensorid", sensor_id},
                                    {"flow_session_id", Flow_Session_Id},
                                    {"nano_timestamp", NanoTimestamp},
                                }},
                                {"body",{
                                        {
                                            SessionStart, // type
                                            {
                                                {"protocol", CurrentPktInfo.protocol},

                                                {"sourceip", CurrentPktInfo.sourceip},
                                                {"sourceport", CurrentPktInfo.sourceport},

                                                {"destinationip", CurrentPktInfo.destinationip},
                                                {"destinationport", CurrentPktInfo.destinationport},

                                                {"interfacename", CurrentPktInfo.iface},

                                                {"direction", CurrentPktInfo.direction}
                                            }
                                        }
                                    }
                                }
                            }
                        );
                        return true;
                    }


                    //2. Session Timeout
                    bool Session_Timeout_Message(
                        std::string Flow_Session_Id,
                        unsigned long long NanoTimestamp,

                        unsigned long long session_lastseen_timestamp, // 해당 세션의 가장 마지막에 저장된 타임스탬프
                        unsigned long long current_timeout_value,        // 현재 적용된 타임아웃 설정값 ( 초 기준 )


                        unsigned long long PktCount,
                        unsigned long long PktCountMaxCycle

                    )
                    {
                        // 세션 시작
                        KAFKA.InsertMessage(
                            {
                                {"header",{
                                    {"sensorid", sensor_id},
                                    {"flow_session_id", Flow_Session_Id},
                                    {"nano_timestamp", NanoTimestamp}
                                }},
                                {"body",{
                                        {
                                            SessionTimeout, // type
                                            {
                                                {"session_lastseen_timestamp", session_lastseen_timestamp},
                                                {"timeout_value", current_timeout_value },

                                                {"pktcount", PktCount },
                                                {"pktcountmaxcycle", PktCountMaxCycle }
                                            }
                                        }
                                    }
                                }
                            }
                        );
                        return true;
                    }

                    //2. Session Timeout
                    bool Session_Rule_Detection_Message(
                        std::string Flow_Session_Id,
                        unsigned long long NanoTimestamp,

                        const SessionRuleDetectInfo& RuleInfo
                    )
                    {
                        // 세션 시작
                        KAFKA.InsertMessage(
                            {
                                {"header",{
                                    {"sensorid", sensor_id},
                                    {"flow_session_id", Flow_Session_Id},
                                    {"nano_timestamp", NanoTimestamp}
                                }},
                                {"body",{
                                        {
                                            SessionRule, // type
                                            {
                                                {"id", RuleInfo.rule_id},
                                                {"description", RuleInfo.rule_description},
                                                {"severity", RuleInfo.severity},

                                                {"stage_node_location_index", RuleInfo.DetectedStage.StageNode},
                                                {"stage_index", RuleInfo.DetectedStage.index},

                                                {"stage_action", RuleInfo.DetectedStage.action.Action},
                                                {"stage_action_message", RuleInfo.DetectedStage.action.message},
                                            }
                                        }
                                    }
                                }
                            }
                        );
                        return true;
                    }

                private:
                    std::string sensor_id;
                    NDR::Util::Kafka::Kafka KAFKA;
                    NDR::Util::Queue::Queue<json> queue;
            };
        }
    }
}

#endif