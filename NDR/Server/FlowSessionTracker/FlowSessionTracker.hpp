#ifndef FLOWSESSIONTRACKER_HPP
#define FLOWSESSIONTRACKER_HPP

#include "../../Util/util.hpp"

namespace NDR
{

    namespace Server
    {
        namespace SessionTracking
        {

            namespace FlowEvent
            {
                class Event
                {
                    public:
                        Event(json event) : jsonEvent(event)
                        {
                            // 이벤트 공통 필드 저장
                            this->SensorId = jsonEvent["header"]["sensorid"].get<std::string>();
                            this->FlowSessionId = jsonEvent["header"]["flow_session_id"].get<std::string>();
                            this->NanoTimestamp = jsonEvent["header"]["nano_timestamp"].get<unsigned long long>();
                        }
                        virtual ~Event() = default;

                        json jsonEvent;

                        std::string SensorId;
                        std::string FlowSessionId;
                        unsigned long long NanoTimestamp;
                };

                class FlowSessionStart : public Event
                {
                    /*
                    {"protocol", CurrentPktInfo.protocol},

                    {"sourceip", CurrentPktInfo.sourceip},
                    {"sourceport", CurrentPktInfo.sourceport},

                    {"destinationip", CurrentPktInfo.destinationip},
                    {"destinationport", CurrentPktInfo.destinationport},

                    {"interfacename", CurrentPktInfo.iface},

                    {"direction", CurrentPktInfo.direction}
                    */
                    public:
                        FlowSessionStart(json event) : Event(event)
                        {
                            this->protocol = event["body"]["session_start"]["protocol"].get<std::string>();

                            this->sourceip = event["body"]["session_start"]["sourceip"].get<std::string>();
                            this->sourceport = event["body"]["session_start"]["sourceport"].get<unsigned long long>();

                            this->destinationip = event["body"]["session_start"]["destinationip"].get<std::string>();
                            this->destinationport = event["body"]["session_start"]["destinationport"].get<unsigned long long>();

                            this->interfacename = event["body"]["session_start"]["interfacename"].get<std::string>();
                            this->direction = event["body"]["session_start"]["direction"].get<std::string>();
                        }

                        std::string protocol;

                        std::string sourceip;
                        unsigned long long sourceport;

                        std::string destinationip;
                        unsigned long long destinationport;

                        std::string interfacename;
                        std::string direction;
                };

                class FlowSessionTimeout : public Event
                {
                    /*
                    {"protocol", CurrentPktInfo.protocol},
                    */
                    public:
                        FlowSessionTimeout(json event) : Event(event)
                        {
                            this->session_lastseen_timestamp = event["body"]["session_timeout"]["session_lastseen_timestamp"].get<unsigned long long>();
                        }

                        unsigned long long session_lastseen_timestamp;
                };

                class FlowSessionRule : public Event
                {

                    enum StageAction
                    {
                        none,
                        notice,
                        block
                    };
                    /*
                        {"id", RuleInfo.rule_id},
                        {"description", RuleInfo.rule_description},
                        {"severity", RuleInfo.severity},

                        {"stage_node_location_index", RuleInfo.DetectedStage.StageNode},
                        {"stage_index", RuleInfo.DetectedStage.index},

                        {"stage_action", RuleInfo.DetectedStage.action.Action},
                        {"stage_action_message", RuleInfo.DetectedStage.action.message}
                    */
                    public:
                        FlowSessionRule(json event) : Event(event)
                        {
                            this->rule_id = event["body"]["session_rule"]["id"].get<std::string>();
                            this->rule_description = event["body"]["session_rule"]["description"].get<std::string>();
                            this->rule_severity = event["body"]["session_rule"]["severity"].get<std::string>();

                            this->stage_node_location_index = event["body"]["session_rule"]["stage_node_location_index"].get<unsigned long long>();
                            this->stage_index = event["body"]["session_rule"]["stage_index"].get<std::string>();

                            std::string action = event["body"]["session_rule"]["stage_action"].get<std::string>();
                            if(action == "notice")
                            {
                                this->stage_action = StageAction::notice;
                            }
                            else if (action == "block")
                            {
                                this->stage_action = StageAction::block;
                            }
                            
                            this->stage_action_message = event["body"]["session_rule"]["stage_action_message"].get<std::string>();
                        }

                        

                        std::string rule_id;
                        std::string rule_description;
                        std::string rule_severity;
                        unsigned long long stage_node_location_index;
                        std::string stage_index;
                        StageAction stage_action = StageAction::none;
                        std::string stage_action_message;
                };
            }

            namespace SessionNode
            {
                struct FlowSessionNode
                {
                    struct 
                    {
                        bool is_enable = false;
                        std::string sensor_id;
                        std::string flow_session_id;
                        struct
                        {
                            // 이 seen 타임스탬프 값은 EDR서버 자체적으로 매기는 것
                            // 로그에서 ["header"]["nano_timestamp"] 값으로 Update
                            unsigned long long first_seen = 0; // first
                            unsigned long long last_seen = 0;  // recent -> (응용): 업데이트가 오래되면 만료처리 가능
                        }seen;
                    }header;

                    std::vector< std::shared_ptr<FlowEvent::Event> > events;

                    json ToJson()
                    {
                        json ObjArray = json::array();
                        for(auto& event : events )
                            ObjArray.push_back(
                                event->jsonEvent
                            );

                        return {
                            {"first_seen", header.seen.first_seen},
                            {"last_seen", header.seen.last_seen},
                            {"events", ObjArray}
                        };
                    }
                };
            }

            class SessionTracker
            {
            public:

                SessionTracker(NDR::Util::Kafka::Kafka_Consumer& Kafka)
                : Kafka(Kafka)
                {

                }
                ~SessionTracker() = default;

                bool Run()
                {
                    if(is_running)
                        return false;

                    is_running = true;
                    EventLoop = std::thread(
                        [this]()
                        {
                            while (this->is_running)
                            {
                                auto Message = this->Kafka.get_message_from_queue();
                                
                                //std::cout << Message.message.dump() << std::endl;
                                if(!Message.message.contains("header") || !Message.message.contains("body") )
                                    continue;
                                
                                std::shared_ptr< FlowEvent::Event > evt = nullptr;
                                if(Message.message["body"].contains("session_start"))
                                {
                                    evt = std::make_shared<FlowEvent::FlowSessionStart>(Message.message); 
                                }
                                else if(Message.message["body"].contains("session_timeout"))
                                {
                                    evt = std::make_shared<FlowEvent::FlowSessionTimeout>(Message.message); 
                                }
                                else if(Message.message["body"].contains("session_rule"))
                                {
                                    evt = std::make_shared<FlowEvent::FlowSessionRule>(Message.message); 
                                }
                                else
                                    continue;

                                
                                auto node = AppendSession(evt);
                                if(node)
                                {
                                    // 후속 작업 ( NDR 실시간 규칙 )
                                }
                            }
                        }
                    );
                    return true;
                }

            private:
                NDR::Util::Kafka::Kafka_Consumer& Kafka;
                std::thread EventLoop;

                bool is_running = false;
                
                
                //std::map<std::string,SessionNode::FlowSessionNode> FlowSessionMap;

                std::map< 
                    std::string,                                        // Sensor ID
                    std::map<std::string,SessionNode::FlowSessionNode>  // NodeMap 
                >FlowSessionMap;
                

                SessionNode::FlowSessionNode* AppendSession(std::shared_ptr< FlowEvent::Event > evt)
                {
                    // 1. Sensor id 찾기 ( 세선 별 세션 기록 )
                    auto& Node_Mapped = FlowSessionMap[evt->SensorId];

                    // 2. Session node 찾기
                    if( dynamic_cast< FlowEvent::FlowSessionStart* >(evt.get()) )
                    {
                        unsigned long long session_timestamp_now = NDR::Util::timestamp::Get_Real_Timestamp();

                        // 세션 생성
                        Node_Mapped[evt->FlowSessionId] = SessionNode::FlowSessionNode{
                            .header = {
                                .is_enable = true,
                                .sensor_id = evt->SensorId,
                                .flow_session_id = evt->FlowSessionId,
                                .seen = {
                                    .first_seen = session_timestamp_now,
                                    .last_seen = session_timestamp_now
                                }
                            }
                        };

                        Node_Mapped[evt->FlowSessionId].events.push_back(evt);/////////////////////////////////////////////
                         return &Node_Mapped[evt->FlowSessionId];
                    }
                    else if ( dynamic_cast< FlowEvent::FlowSessionTimeout* >(evt.get()) )
                    {
                        // 세션 타임아웃
                        if( Node_Mapped.find(evt->FlowSessionId) == Node_Mapped.end() )
                            return nullptr;
                        
                        // last_seen - update
                        Node_Mapped[evt->FlowSessionId].header.seen.last_seen = NDR::Util::timestamp::Get_Real_Timestamp();

                        // timeout struct
                        Node_Mapped[evt->FlowSessionId].events.push_back(evt);/////////////////////////////////////////////

                        Node_Mapped[evt->FlowSessionId].header.is_enable = false; // disable 처리

                        std::cout << "SESSION_OUT :: " << Node_Mapped[evt->FlowSessionId].ToJson() << std::endl;
                        
                        return &Node_Mapped[evt->FlowSessionId];
                    }
                    else
                    {
                        if( Node_Mapped.find(evt->FlowSessionId) == Node_Mapped.end() )
                            return nullptr;

                        // last_seen - update
                        Node_Mapped[evt->FlowSessionId].header.seen.last_seen = NDR::Util::timestamp::Get_Real_Timestamp();

                        Node_Mapped[evt->FlowSessionId].events.push_back(evt);/////////////////////////////////////////////
                        return &Node_Mapped[evt->FlowSessionId];
                    }


                }
                
            };
        }
    }
}


#endif