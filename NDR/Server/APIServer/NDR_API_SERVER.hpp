#ifndef APISERVER_HPP
#define APISERVER_HPP

#include "../../Util/util.hpp"
#include "../NDRServer.hpp"

namespace NDR
{
    namespace Server
    {
        // API PATH
        constexpr char* QueryALL = "/api/solution/ndr/query/all";

        namespace API
        {
            class APIServer 
            {
            private:
                NDR::Server::NDRServer& NDR_Backend;

                std::string APIServerIP;
                unsigned int APIServerPORT;

                httplib::Server APIsvr;

            public:
            
                APIServer(
                    std::string APIServerIP, 
                    unsigned int APIServerPORT,
                    
                    // NDR Backend
                    NDR::Server::NDRServer& NDR_Backend
                ) : 
                APIServerIP(APIServerIP), 
                APIServerPORT(APIServerPORT),
                NDR_Backend(NDR_Backend)
                {

                }
                ~APIServer(){ Stop(); }


                bool Runner()
                {
                    if(is_working)
                        return false;

                    is_working= true;

                    // ==================================================

                    // 1. Query
                    // -> 1.A. ALL
                    // -> 2.A. Sensor query

                    // 2. Response
                    // -> 2.A. Network

                    // ==================================================


                    // -> 1.A. ALL
                    APIsvr.Get(
                        QueryALL,
                        Query_all_function
                    );

                    // -> 2.A. Sensor query
                    APIsvr.Get(
                        QueryALL,
                        Query_sensor_function
                    );

                    APIsvr.listen(APIServerIP, APIServerPORT);
                }

                bool Stop(){
                    if(!is_working)
                        return false;

                    is_working = false;
                    this->APIsvr.stop();

                    return true;
                }

                // -> 1.A. ALL
                std::function<void(const httplib::Request&, httplib::Response&)> Query_all_function = 
                [this](const httplib::Request& req, httplib::Response& res)
                {
                    std::string fail_reason = "";
                    json success_result_output;

                    /*
                    
                        <query json>
                    
                    */


                    SUCCESS:
                    {
                        this->set_success_response(success_result_output, res);
                        return;
                    }
                    FAIL:
                    {
                        this->set_fail_response(fail_reason, res);
                        return;
                    }
                };

                // -> 2.A. Sensor query
                std::function<void(const httplib::Request&, httplib::Response&)> Query_sensor_function = 
                [this](const httplib::Request& req, httplib::Response& res)
                {
                    std::string fail_reason = "";
                    json success_result_output;

                    /*
                    
                        <query json>
                    
                    */


                    SUCCESS:
                    {
                        this->set_success_response(success_result_output, res);
                        return;
                    }
                    FAIL:
                    {
                        this->set_fail_response(fail_reason, res);
                        return;
                    }
                };
                
            private:
                

                std::atomic<bool> is_working = false;

                // helper
                
                // 1. text to json
                json _text_to_json(const std::string Body)
                {
                    try
                    {
                        return json::parse(Body);
                    }
                    catch (const std::exception& e)
                    {
                        throw e.what();
                    }
                }

                 // 2. Failed JSON Output
                bool set_fail_response(std::string reason, httplib::Response& res)
                {
                    json body = {
                        {"status", false},
                        {"fail_reason", reason}
                    };

                    res.set_content(body.dump(), "application/json");

                    return true;
                }
                bool set_success_response(json output, httplib::Response& res)
                {
                    json body = {
                        {"status", true},
                        {"output", output}
                    };

                    res.set_content(body.dump(), "application/json");

                    return true;
                }
            };

           
        }
    }
}

#endif