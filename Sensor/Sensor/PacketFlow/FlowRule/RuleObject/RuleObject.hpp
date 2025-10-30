#ifndef RuleObject_HPP
#define RuleObject_HPP

#include "../../../../util/util.hpp"

#include "FlowRuleDef.hpp"
#include "../../../LogSender/LogSender.hpp"

#include <pcapplusplus/Packet.h>


namespace NDR
{
    namespace Sensor
    {
        namespace FlowRule
        {
            namespace RuleObject
            {
                class RuleObject;

                enum RuleDirection
                {
                    INGRESS=1,
                    EGRESS
                };

                struct RuleTimestamp
                {
                    unsigned long long within = 0; // ns 단위
                };

                struct RuleAction
                {
                    std::string type;
                    std::string message;
                };

                struct RuleThreshold
                {
                    unsigned long long PktCount;
                };

                struct RulePre
                {
                    /*
                        MAP
                            key: id (string)
                            value: 해당 Object의 complete_count 참조
                    */
                    std::optional< std::vector<std::string > > not_complete_ids; // 시퀀스 최초 1회이상 회전하지 못한 ids MAPS
                    std::optional< std::vector<std::string> > complete_ids;     // 시퀀스 최초 1회이상 회전한 ids MAPS
                    
                };

                struct RuleSequence
                {
                    std::string index;
                    std::optional<RuleAction> action = std::nullopt;

                    // match resources
                    NDR::Sensor::FlowRule::RuleDef::RuleConditionObject conditionManager;
                    std::optional<RuleTimestamp> timestamp = std::nullopt;
                    std::optional<RuleDirection> direction = std::nullopt;
                    std::optional<RuleThreshold> threshold = std::nullopt;
                    std::optional<unsigned long long> Goto = std::nullopt; // goto (index이동)

                    std::optional<RulePre> Pre = std::nullopt;
                };

                // Stored Rule - CTX
                struct RuleObject_CTX
                {
                    NDR::Sensor::FlowRule::RuleObject::RuleThreshold Threshold;             // ThresHold current
                };


                class RuleObject
                {
                public:
                    bool is_enable = false;
                    
                    std::string id;
                    std::string description;
                    std::string severity;
                    std::vector<RuleSequence> sequence;


                    RuleObject(NDR::Sensor::LogSender::Logger& Logger, json RuleJson)
                    :Logger(Logger)
                    {
                        id = RuleJson.value("id", "");
                        description = RuleJson.value("description", "");
                        severity = RuleJson.value("severity", "");

                        // 1. Seq각 Index 문자열과 인덱스값간 매핑
                        unsigned long long index_index = 0;
                        std::map<std::string, unsigned long long > RuleIndexwithIndexMap;
                        for(auto& seq_element: RuleJson.at("sequence"))
                        {
                            RuleIndexwithIndexMap[seq_element.value("index", "")] = index_index;
                            ++index_index;
                        }

                        // 본격적인 시퀀스 로직처리
                        for(auto& seq_element: RuleJson.at("sequence"))
                        {
                            RuleSequence Seq;
                            Seq.index = seq_element.value("index", ""); // "index"(string)

                            // goto 추가
                            if( seq_element.contains("goto") )
                            {
                                std::string goto_target_index = seq_element["goto"].get<std::string>();

                                Seq.Goto.emplace(
                                    RuleIndexwithIndexMap[goto_target_index]
                                );
                            }

                            // condition 추가
                            Seq.conditionManager.InsertRule(
                                seq_element["condition"]
                            );
                            std::cout << "conditionManager-->InsertRule 호출된" << std::endl;

                            // threshold
                            if( seq_element.contains("threshold") )
                            {
                                auto threshold = seq_element["threshold"];
                                if(threshold.contains("pktcount"))
                                {
                                    unsigned long long pktcount = threshold["pktcount"].get<unsigned long long>();
                                    if(pktcount)
                                    {
                                        Seq.threshold.emplace(
                                            RuleThreshold{
                                                .PktCount = pktcount
                                            }
                                        );
                                    }
                                }

                            }

                            // direction
                            if( seq_element.contains("direction") )
                            {
                                std::string direction_ = seq_element["direction"].get<std::string>();
                                
                                if(!direction_.empty())
                                {
                                    std::transform(direction_.begin(), direction_.end(), direction_.begin(), ::toupper); // 대문자 취급

                                    

                                    if ( direction_ == "INGRESS" || direction_ == "IN" ) 
                                        Seq.direction.emplace(INGRESS);
                                    else if (direction_ == "EGRESS" || direction_ == "OUT") 
                                        Seq.direction.emplace(EGRESS);
                                    else
                                        throw std::runtime_error("Unknown direction type");

                                }
                            }

                            // Action
                            if( seq_element.contains("action") )
                            {
                                Seq.action.emplace(); // optional (std::nullopt에서 유효한 상태로 변경(필수) )

                                Seq.action->type = seq_element["action"].value("type", "");
                                Seq.action->message = seq_element["action"].value("message", "");
                            }

                            // Pre 키가 있는 경우, emplace로 초기화
                            if( seq_element.contains("pre") )
                            {
                                seq_element["pre"];

                                Seq.Pre.emplace();

                                // not_complete_ids ?
                                if( seq_element["pre"].contains("not_complete_ids") )
                                {
                                    std::vector< std::string > not_complete_ids_vec = seq_element["pre"]["not_complete_ids"].get<std::vector< std::string >>();
                                    if(not_complete_ids_vec.size())
                                    {
                                        Seq.Pre->not_complete_ids.emplace();
                                        for(auto& id_string : not_complete_ids_vec)
                                        {
                                            (Seq.Pre->not_complete_ids.value()).push_back(id_string); // 등록할 id 명
                                        }
                                    }

                                }

                                // complete_ids ?
                                if( seq_element["pre"].contains("complete_ids") )
                                {
                                    std::vector< std::string > complete_ids_vec = seq_element["pre"]["complete_ids"].get<std::vector< std::string >>();
                                    if(complete_ids_vec.size())
                                    {
                                        Seq.Pre->complete_ids.emplace();
                                        for(auto& id_string : complete_ids_vec)
                                        {
                                            (Seq.Pre->complete_ids.value()).push_back(id_string); // 등록할 id 명
                                        }
                                    }
                                }

                            }

                            sequence.push_back(std::move(Seq));
                            ++index_index;
                        }

                        std::cout << "RuleObject 클래스 생성된" << std::endl;
                        is_enable = false;

                    }

                    ~RuleObject() = default;
                    
                    bool Match(

                        

                        // Session Info
                        const std::string& SessionID,

                        // Live Data - From Session Execlusive Node
                        const pcpp::Packet& pkt,
                        const RuleDirection direction,
                        const unsigned long long PacketTimestamp,
                        

                        // Stored Data - From Session Execlusive Node
                        RuleObject_CTX& CTX,
                        unsigned long long* next_Sequence_index, // JSON 규칙에서 여러 conditions 배열안에서, 이순간 바로 match 해야할 index값을 의미 (0부터 시작)
                        std::map<std::string,unsigned long long>& RulesSequenceCycleCount
                    )
                    {
                        int current_index = 0;
                        for(auto& seq_element : sequence)
                        {
                            if(*next_Sequence_index == current_index)
                            {
                                /*
                                    Current Match Index
                                */

                                // + Packet-Condition Match
                                if( !seq_element.conditionManager.Match(pkt) )
                                    return false;
                                

                                // + Pre Match
                                if( !_Pre_Match(seq_element, RulesSequenceCycleCount) )
                                    return false;

                                // + Direction Match  (if none std::nullopt)
                                if( !_Direction_Match(seq_element, direction) )
                                    return false;

                                // + Threshold Match
                                if( !_Threshold_Match(seq_element, CTX) )
                                    return false;

                                /*
                                    SUCCESS
                                */
                                std::cout << seq_element.index << std::endl;
                                // complete_count 1증가할 지 확인.
                                std::cout << "*next_Sequence_index: " << *next_Sequence_index << " || sequence.size(): " << sequence.size() << std::endl;
                                if( *next_Sequence_index == ( sequence.size() - 1) )
                                {
                                    std::cout << fmt::format("id: {} / CTX.RulesSequenceCycleCount[rule_id]: {} ", id, RulesSequenceCycleCount[id]) << std::endl;
                                    RulesSequenceCycleCount[id] += 1; // RUle Sequence 전체 한번 돌았으므로 ++1 
                                    std::cout << "다돌았다" << std::endl;
                                }
                                    



                                //"goto"가 있는 경우,  해당 인덱스로 이동
                                if( seq_element.Goto.has_value() )
                                {
                                    *next_Sequence_index = seq_element.Goto.value(); // 고정으로 정해진 "goto" index로 설정
                                }
                                else{
                                    *next_Sequence_index += 1; // 다음 Sequence 인덱스로 이동 * 만약 "sequence.size()"값과 동일하다면, 더이상 해당 규칙은 작동하지 않음.
                                }

                                return true;
                                
                            }
                            ++current_index;
                        }
                        return false;
                    }

                private:
                    NDR::Sensor::LogSender::Logger& Logger;

                    bool _Pre_Match(RuleSequence& seq_element, std::map<std::string,unsigned long long>& RulesSequenceCycleCount)
                    {
                        if(seq_element.Pre.has_value())
                        {
                            
                            if(seq_element.Pre.value().not_complete_ids.has_value() )
                            {
                                /*
                                    not_complete 는 등록된 id 규칙에서 시퀀스가 모두 돌지 않았을 때 true를 반환
                                    1번 이상 돌았다면, false 반환
                                */
                                auto& not_complete = seq_element.Pre.value().not_complete_ids.value() ;
                                for( auto& rule_id : not_complete )
                                {
                                    if( RulesSequenceCycleCount[rule_id] >= 1 )
                                    {
                                        return false;
                                    }
                                }
                                std::cout << "PRE성공" << std::endl;
                            }

                            if(seq_element.Pre.value().complete_ids.has_value() )
                            {
                                /*
                                    complete 는 등록된 id 규칙에서 시퀀스가 모두 한번이상 돌았을 때 true를 반환
                                    그 어느것 규칙object에서 못 돌았다면, false 반환
                                */
                                auto& complete = seq_element.Pre.value().complete_ids.value();
                                for( auto& rule_id : complete )
                                {
                                        if( RulesSequenceCycleCount[rule_id] == 0 )
                                    {
                                        return false;
                                    }
                                }
                                std::cout << "PRE성공" << std::endl;
                            }

                            
                        }
                        return true;
                    }

                    bool _Threshold_Match(RuleSequence& seq_element, RuleObject_CTX& CTX)
                    {
                        if( seq_element.threshold.has_value() )
                        {
                            CTX.Threshold.PktCount += 1; // 현재 패킷 카운트

                            /* seq_element.threshold 가 nullopt가 아닌 경우는 Threshold 옵션 매치가 필요하다는 뜻. */
                            if( seq_element.threshold->PktCount > CTX.Threshold.PktCount )
                            {
                                // 아직 "CTX.Threshold.PktCount" 패킷카운트 값이 작은 경우 ...
                                std::cout << "seq_element.threshold->PktCount: " << seq_element.threshold->PktCount << "CTX.Threshold.PktCount" << CTX.Threshold.PktCount << std::endl;
                                return false; // 아직더 카운트가 필요.
                            }
                        }

                        return true;
                    }
                    bool _Direction_Match(RuleSequence& seq_element, const RuleDirection LiveData_Direction)
                    {
                        if(seq_element.direction.has_value())
                        {
                            if( seq_element.direction.value() != LiveData_Direction )
                                return false;
                        }
                        return true;
                    }
                };
            }
        }
    }
}

#endif