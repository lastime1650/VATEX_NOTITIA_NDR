#ifndef RuleObject_HPP
#define RuleObject_HPP

#include "../../../../util/util.hpp"

#include "FlowRuleDef.hpp"

#include <pcapplusplus/Packet.h>

namespace NDR
{
    namespace Sensor
    {
        namespace FlowRule
        {
            namespace RuleObject
            {
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

                struct RuleSequence
                {
                    std::string index;
                    std::optional<RuleAction> action = std::nullopt;

                    // match resources
                    NDR::Sensor::FlowRule::RuleDef::RuleConditionObject conditionManager;
                    std::optional<RuleTimestamp> timestamp = std::nullopt;
                    std::optional<RuleDirection> direction = std::nullopt;
                    std::optional<RuleThreshold> threshold = std::nullopt;
                };

                // Stored Rule - CTX
                struct RuleObject_CTX
                {
                    NDR::Sensor::FlowRule::RuleObject::RuleThreshold Threshold;             // ThresHold current
                };


                class RuleObject
                {
                public:
                    std::string id;
                    std::string description;
                    std::vector<RuleSequence> sequence;
                    //unsigned long long next_needs_condition_index = 0;// condtion check가 필요한 index 값


                    RuleObject(json RuleJson){
                        id = RuleJson.value("id", "");
                        description = RuleJson.value("description", "");

                        for(auto& seq_element: RuleJson.at("sequence"))
                        {
                            RuleSequence Seq;
                            Seq.index = seq_element.value("index", "");

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

                            sequence.push_back(std::move(Seq));
                            
                        }

                        std::cout << "RuleObject 클래스 생성된" << std::endl;

                    }

                    ~RuleObject() = default;

                    
                    bool Match(
                        // Live Data - From Session Execlusive Node
                        const pcpp::Packet& pkt,
                        const RuleDirection direction,
                        

                        // Stored Data - From Session Execlusive Node
                        RuleObject_CTX& CTX,
                        unsigned long long* next_condition_index // JSON 규칙에서 여러 conditions 배열안에서, 이순간 바로 match 해야할 index값을 의미 (0부터 시작)
                    )
                    {
                        //if(next_condition_index >= 1)
                            //std::cout << "Rule Request Index: " << next_condition_index << std::endl;
                        int current_index = 0;
                        for(auto& seq_element : sequence)
                        {
                            if(*next_condition_index == current_index)
                            {
                                /*
                                    Current Match Index
                                */

                                // + Packet-Condition Match
                                if( !seq_element.conditionManager.Match(pkt) )
                                    goto Failed;

                                std::cout << "Rule--매치됨" << std::endl;

                                // + Direction Match  (if none std::nullopt)
                                if(seq_element.direction.has_value())
                                {
                                    if( seq_element.direction.value() != direction )
                                        goto Failed;
                                }

                                // + Threshold Match
                                if( seq_element.threshold.has_value() )
                                {
                                    CTX.Threshold.PktCount += 1; // 현재 패킷 카운트

                                    std::cout << "Threshold Match -> " << std::endl;
                                    /* seq_element.threshold 가 nullopt가 아닌 경우는 Threshold 옵션 매치가 필요하다는 뜻. */
                                    if( seq_element.threshold->PktCount > CTX.Threshold.PktCount )
                                    {
                                        // 아직 "CTX.Threshold.PktCount" 패킷카운트 값이 작은 경우 ...
                                        std::cout << "seq_element.threshold->PktCount: " << seq_element.threshold->PktCount << "CTX.Threshold.PktCount" << CTX.Threshold.PktCount << std::endl;
                                        goto Failed; // 아직더 카운트가 필요.
                                    }
                                }

                                

                                
                                goto Success;


                                Failed:
                                {
                                    return true;
                                }
                                Success:
                                {
                                    *next_condition_index += 1; // 다음 Sequence 인덱스로 이동
                                    return false;
                                }
                            }
                            ++current_index;
                        }
                        return false;
                    }
                };
            }
        }
    }
}

#endif