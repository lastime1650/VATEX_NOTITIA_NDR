#ifndef FlowRuleManager_HPP
#define FlowRuleManager_HPP

#include "../../../util/util.hpp"
#include "RuleObject/RuleObject.hpp"
#include "../../LogSender/LogSender.hpp"

namespace NDR
{
    namespace Sensor
    {
        namespace FlowRule
        {
            

            struct RuleObjectForSession
            {
                /*
                    Rule Logics
                */
                std::shared_ptr< NDR::Sensor::FlowRule::RuleObject::RuleObject> Rule;    //Condition Logics
                
                /*
                    Stored Data
                */
                struct NDR::Sensor::FlowRule::RuleObject::RuleObject_CTX CTX;
                unsigned long long currentIndex = 0;
            };



            class FlowRuleManager
            {
                public:
                    FlowRuleManager(NDR::Sensor::LogSender::Logger& Logger, std::string RuleDir)
                    : Logger(Logger),
                    RuleDir(RuleDir)
                    {
                        if( !this->Reload_Rules() )
                            std::cout << "NoneRules at Init" << std::endl;
                    }

                    ~FlowRuleManager() = default;

                    bool Reload_Rules()
                    {
                        return _rule_reload();
                    }

                    std::vector< RuleObjectForSession > Get_Rules()
                    {
                        return rules; // 복사본 반환
                    }

                private:
                    std::string RuleDir; // example) ./test/dir
                    NDR::Util::File::FileHandler FileHandle;

                    std::vector< RuleObjectForSession > rules;

                    NDR::Sensor::LogSender::Logger& Logger;


                    bool _get_rule_file_paths(std::vector<std::filesystem::path>& output)
                    {
                        std::string recent_rule_dir_path = RuleDir;
                        
                        try {
                            if (std::filesystem::exists(recent_rule_dir_path) && std::filesystem::is_directory(recent_rule_dir_path)) {
                                for (const auto& entry : std::filesystem::directory_iterator(recent_rule_dir_path)) {
                                    if (std::filesystem::is_regular_file(entry.path())) {
                                        output.push_back( std::filesystem::absolute(entry.path()) ); // 절대경로
                                    }
                                }
                                // 파일이 하나도 없는 경우도 유효한 상태이므로 false를 반환하지 않습니다.
                                return true;
                            } else {
                                //std::cerr << "디렉터리가 존재하지 않거나 올바르지 않습니다: " << recent_rule_dir_path << std::endl;
                                return false;
                            }
                        } catch (const std::filesystem::filesystem_error& e) {
                            //std::cerr << "파일 시스템 오류: " << e.what() << std::endl;
                            return false;
                        }
                    }

                    bool _rule_reload()
                    {

                        rules.clear();

                        std::vector<std::filesystem::path> rule_abs_paths;
                        if(!_get_rule_file_paths(rule_abs_paths) || rule_abs_paths.size() == 0)
                            return false;
                        
                        std::cout << rule_abs_paths.size() << std::endl;

                        // 규칙을 디스크로부터 읽고 json으로 변환하여 등록
                        for(const auto& path : rule_abs_paths)
                        {
                            auto JSON_BIN = FileHandle.readFromFile(path.string());
                            if(JSON_BIN.empty())
                                continue;
                            std::cout << "JSON PATH: " << path.string() << std::endl;
                            std::cout << "JSON STRING SIZE: " << JSON_BIN.size() << std::endl;

                            try{
                                json RULE = json::parse( std::string( JSON_BIN.begin(), JSON_BIN.end() ) );
                                if(!RULE.contains("id"))
                                    throw std::runtime_error("RULE hasn't id key in file: " + path.string());

                                // json::value()를 사용하여 안전하게 id를 문자열로 가져옵니다.
                                std::string rule_id = RULE.value("id", "");
                                if (rule_id.empty()) {
                                    throw std::runtime_error("RULE has an empty id in file: " + path.string());
                                }

                                // Rule JSON객체 저장

                                rules.push_back(
                                    RuleObjectForSession{
                                        .Rule = std::make_shared< NDR::Sensor::FlowRule::RuleObject::RuleObject >(Logger, RULE),
                                        .currentIndex = 0
                                    }
                                    //std::make_shared< NDR::Sensor::FlowRule::RuleObject::RuleObject >(RULE)
                                );


                            } catch (const std::exception& e)
                            {
                                std::cerr << "Rule parsing error: " << e.what() << std::endl;
                                continue;
                            }
                        }

                        return true;
                    }
                    
            };
        }   
    }
}

#endif