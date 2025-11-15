#ifndef FLOWSESSIONTRACKER_HPP
#define FLOWSESSIONTRACKER_HPP

#include "../../Util/util.hpp"
#include "../AIMananger/AIManager.hpp"

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

                            this->egress_packet_count = jsonEvent["header"]["current_egress_packet_count"].get<unsigned long long>();
                            this->ingress_packet_count = jsonEvent["header"]["current_ingress_packet_count"].get<unsigned long long>();
                            this->egress_packet_countCycle = jsonEvent["header"]["current_egress_packet_cycle_count"].get<unsigned long long>();
                            this->ingress_packet_countCycle = jsonEvent["header"]["current_ingress_packet_cycle_count"].get<unsigned long long>();

                            this->current_packet_ALL_size = jsonEvent["header"]["current_packet_size"].get<unsigned long long>();
                            this->current_packet_size_cycle_count = jsonEvent["header"]["current_packet_size_cycle_count"].get<unsigned long long>();
                        }
                        virtual ~Event() = default;

                        void Set_PacketStatus(const json& arg_PacketStatus)
                        {
                            this->PacketStatus = arg_PacketStatus;
                        }
                        std::optional<json> Get_PacketStatus()
                        {
                            return this->PacketStatus;
                        }

                        void Set_PacketJson(const json& arg_PacketJson)
                        {
                            this->PacketJson = arg_PacketJson;
                        }
                        std::optional<json> Get_PacketJson()
                        {
                            return this->PacketJson;
                        }

                        json jsonEvent;

                        std::optional<json> PacketStatus = std::nullopt;
                        std::optional<json> PacketJson = std::nullopt;

                        std::string SensorId;
                        std::string FlowSessionId;
                        unsigned long long NanoTimestamp;

                        unsigned long long egress_packet_count=0;
                        unsigned long long ingress_packet_count=0;
                        unsigned long long egress_packet_countCycle=0;
                        unsigned long long ingress_packet_countCycle=0;

                        unsigned long long current_packet_ALL_size;
                        unsigned long long current_packet_size_cycle_count;
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

                            Event::Set_PacketJson( event["body"]["packet"] );
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
                            
                            Event::Set_PacketStatus( event["body"]["status"] );
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

                            Event::Set_PacketStatus( event["body"]["status"] );
                            Event::Set_PacketJson( event["body"]["packet"] );
                            
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

                        unsigned long long egress_packet_count=0;
                        unsigned long long ingress_packet_count=0;
                        unsigned long long egress_packet_countCycle=0;
                        unsigned long long ingress_packet_countCycle=0;

                        unsigned long long packetsize = 0;
                        unsigned long long packetsizecyclecount = 0;
                    }header;

                    std::vector< std::shared_ptr<FlowEvent::Event> > events;
                    json PacketStatus = json::object(); // 비투명구조. Sensor에서 2차원구조의 JSON으로 Flatten된 패킷 전체 누적값
                    std::vector< json > PacketJsons;    // 발각된 당시 패킷 값

                    void Set_PacketStatus(const json& Status_Value)
                    {
                        PacketStatus = Status_Value;
                    }
                    void Append_PacketJson(const json& packet_Value)
                    {
                        PacketJsons.push_back(packet_Value);
                    }

                    json ToJson()
                    {
                        json EventArray = json::array();
                        for(auto& event : events )
                        {
                            auto JsonCopied = event->jsonEvent;
                            if( JsonCopied["body"].contains("status") )
                                JsonCopied["body"].erase("status");
                            if( JsonCopied["body"].contains("packet") )
                                JsonCopied["body"].erase("packet");
                            

                            EventArray.push_back(
                                JsonCopied
                            );
                        }

                        return json::object(
                            {
                                {"sensor_id", header.sensor_id},

                                {"flow_session_id", header.flow_session_id},
                                {"event_count", events.size()},

                                {"egress_packet_count", header.egress_packet_count },
                                {"egress_packet_cycle_count", header.egress_packet_countCycle },
                                {"ingress_packet_count", header.ingress_packet_count },
                                {"ingress_packet_cycle_count", header.ingress_packet_countCycle },

                                { "timestamp", {
                                    {"first_seen", header.seen.first_seen},
                                    {"last_seen", header.seen.last_seen},
                                    {"first_seen_iso8601", NDR::Util::timestamp::To_Nano_Iso8601(header.seen.first_seen)},
                                    {"last_seen_iso8601", NDR::Util::timestamp::To_Nano_Iso8601(header.seen.last_seen)}
                                } },

                                {"events", EventArray },
                                {"status", PacketStatus},
                                {"packets", PacketJsons}

                            }
                        );
                    }
                };
            }

            class SessionTracker
            {
            public:

                std::thread PacketFinishedThread;

                SessionTracker(
                    NDR::Util::Kafka::Kafka_Consumer& Kafka,

                    NDR::AI::AI_MANAGER& AIManager,
                    NDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& IntelligenceManager,
                    NDR::Util::ToSiem::SiemClient& SiemClient
                )
                : Kafka(Kafka),

                AIManager(AIManager),
                IntelligenceManager(IntelligenceManager),
                SiemClient(SiemClient)
                {}
                ~SessionTracker() = default;

                bool Run()
                {
                    if(is_running)
                        return false;

                    is_running = true;

                    // 마감 패킷 처리
                    PacketFinishedThread = std::thread( &SessionTracker::PostfixFinishingLoop, this );


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

                                //std::cout << Message.message.dump() << std::endl;
                                AppendSession(evt);
                            }
                        }
                    );
                    return true;
                }

            private:
                NDR::Util::Kafka::Kafka_Consumer& Kafka;
                std::thread EventLoop;

                bool is_running = false;

                NDR::AI::AI_MANAGER& AIManager;
                NDR::Util::Intelligence::VATEX_INTELLINA_INTELLIGENCE& IntelligenceManager;
                NDR::Util::ToSiem::SiemClient& SiemClient;
                
                
                //std::map<std::string,SessionNode::FlowSessionNode> FlowSessionMap;

                std::map< 
                    std::string,                                        // Flow ID
                    std::map<std::string, std::shared_ptr< SessionNode::FlowSessionNode > >  // NodeMap < k:SessionId, v:nodeStruct >
                >FlowSessionMap;
                

                bool AppendSession(std::shared_ptr< FlowEvent::Event > evt)
                {
                    // 1. Sensor id 찾기 ( 세선 별 세션 기록 )
                    auto& Node_Mapped = FlowSessionMap[evt->SensorId];

                    // 2. Session node 찾기
                    if( dynamic_cast< FlowEvent::FlowSessionStart* >(evt.get()) )
                    {
                        unsigned long long session_timestamp_now = NDR::Util::timestamp::Get_Real_Timestamp();

                        auto Node = SessionNode::FlowSessionNode{};
                        Node.header.is_enable = true;
                        Node.header.sensor_id = evt->SensorId;
                        Node.header.flow_session_id = evt->FlowSessionId;

                        Node.header.seen.first_seen = session_timestamp_now;
                        Node.header.seen.last_seen = session_timestamp_now;

                        Node.header.packetsize = evt->current_packet_ALL_size;
                        Node.header.packetsizecyclecount = evt->current_packet_size_cycle_count;

                        Node.header.egress_packet_count = evt->egress_packet_count;
                        Node.header.ingress_packet_count = evt->ingress_packet_count;
                        Node.header.egress_packet_countCycle =  evt->egress_packet_countCycle;
                        Node.header.ingress_packet_countCycle = evt->ingress_packet_countCycle;

                        // 세션 생성
                        Node_Mapped[evt->FlowSessionId] = std::make_shared<SessionNode::FlowSessionNode>(Node);


                        Node_Mapped[evt->FlowSessionId]->events.push_back(evt);/////////////////////////////////////////////

                        if( evt->Get_PacketJson().has_value() )
                            Node_Mapped[evt->FlowSessionId]->Append_PacketJson( evt->Get_PacketJson().value() );


                        return true;
                    }
                    else if ( dynamic_cast< FlowEvent::FlowSessionTimeout* >(evt.get()) )
                    {
                        // 세션 타임아웃
                        if( Node_Mapped.find(evt->FlowSessionId) == Node_Mapped.end() )
                            return false;
                        
                        if(!Node_Mapped[evt->FlowSessionId]) // check nullptr
                            return false;

                        // last_seen - update
                        Node_Mapped[evt->FlowSessionId]->header.seen.last_seen = NDR::Util::timestamp::Get_Real_Timestamp();

                        // 패킷 카운트 업데이트
                        Node_Mapped[evt->FlowSessionId]->header.ingress_packet_count = evt->ingress_packet_count;
                        Node_Mapped[evt->FlowSessionId]->header.ingress_packet_countCycle = evt->ingress_packet_countCycle;
                        Node_Mapped[evt->FlowSessionId]->header.egress_packet_count = evt->egress_packet_count;
                        Node_Mapped[evt->FlowSessionId]->header.egress_packet_countCycle = evt->egress_packet_countCycle;

                        // 패킷 사이즈 업데이트
                        Node_Mapped[evt->FlowSessionId]->header.packetsize = evt->current_packet_ALL_size;
                        Node_Mapped[evt->FlowSessionId]->header.packetsizecyclecount = evt->current_packet_size_cycle_count;

                        // timeout struct
                        Node_Mapped[evt->FlowSessionId]->events.push_back(evt);/////////////////////////////////////////////

                        Node_Mapped[evt->FlowSessionId]->header.is_enable = false; // disable 처리

                        if( evt->Get_PacketStatus().has_value() )
                            Node_Mapped[evt->FlowSessionId]->Set_PacketStatus( evt->Get_PacketStatus().value() );

                        FlowSessionQueue.put( std::move( Node_Mapped[evt->FlowSessionId] ) );
                        return true;
                    }
                    else
                    {
                        if( Node_Mapped.find(evt->FlowSessionId) == Node_Mapped.end() )
                            return false;

                        // 패킷 카운트 업데이트
                        Node_Mapped[evt->FlowSessionId]->header.ingress_packet_count = evt->ingress_packet_count;
                        Node_Mapped[evt->FlowSessionId]->header.ingress_packet_countCycle = evt->ingress_packet_countCycle;
                        Node_Mapped[evt->FlowSessionId]->header.egress_packet_count = evt->egress_packet_count;
                        Node_Mapped[evt->FlowSessionId]->header.egress_packet_countCycle = evt->egress_packet_countCycle;

                        // 패킷 사이즈 업데이트
                        Node_Mapped[evt->FlowSessionId]->header.packetsize = evt->current_packet_ALL_size;
                        Node_Mapped[evt->FlowSessionId]->header.packetsizecyclecount = evt->current_packet_size_cycle_count;

                        // last_seen - update
                        Node_Mapped[evt->FlowSessionId]->header.seen.last_seen = NDR::Util::timestamp::Get_Real_Timestamp();

                        Node_Mapped[evt->FlowSessionId]->events.push_back(evt);/////////////////////////////////////////////

                        if( evt->Get_PacketStatus().has_value() )
                            Node_Mapped[evt->FlowSessionId]->Set_PacketStatus( evt->Get_PacketStatus().value() );
                        
                        if( evt->Get_PacketJson().has_value() )
                            Node_Mapped[evt->FlowSessionId]->Append_PacketJson( evt->Get_PacketJson().value() );


                        return true;
                    }


                }

                bool print_tested = false;
                // Postfix Session
                void PostfixFinishingLoop()
                {
                    std::cout << "PostfixFinishingLoop Starting ... " << std::endl;
                    while(is_running)
                    {
                        auto FlowSessionNode = FlowSessionQueue.get();
                        
                        if(!print_tested)
                        {
                            std::cout << FlowSessionNode->ToJson().dump();
                            print_tested = true;
                        }

                        //_session_to_json(FlowSessionNode);
                    }
                }
                NDR::Util::Queue::Queue<std::shared_ptr< SessionNode::FlowSessionNode >> FlowSessionQueue;

                

                std::vector<double> _session_to_AI_sample(const std::shared_ptr<NDR::Server::SessionTracking::SessionNode::FlowSessionNode>& sessionNode)
                {
                    return {};
                }

                bool __AI_sample_SessionInfo(
                    const std::shared_ptr<NDR::Server::SessionTracking::SessionNode::FlowSessionNode>& sessionNode,
                    std::vector<double>& Sample
                )
                {
                    return true;
                }

                bool __AI_sample_RuleInfo(
                    const std::shared_ptr<NDR::Server::SessionTracking::SessionNode::FlowSessionNode>& sessionNode,
                    std::vector<double>& Sample
                )
                {
                    return true;
                }

                bool __AI_sample_IntelligenceInfo(
                    const std::shared_ptr<NDR::Server::SessionTracking::SessionNode::FlowSessionNode>& sessionNode,
                    std::vector<double>& Sample
                )
                {
                    return true;
                }

                
                
            };
        }
    }
}


#endif