#ifndef PACKETFLOWRULEDEFINITE_HPP
#define PACKETFLOWRULEDEFINITE_HPP

#include <unordered_map>
#include <string>
#include <vector>
#include <optional>
#include <memory>
#include <iostream>
#include <algorithm>
#include <cmath>
#include <array>
#include <regex> // <regex> 헤더 추가

#include "../../../../util/util.hpp" // json, etc.

#include <pcapplusplus/Packet.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/ArpLayer.h>
#include <pcapplusplus/IPLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/SSLLayer.h>
#include <pcapplusplus/SSLHandshake.h>
#include <pcapplusplus/Layer.h>
#include <pcapplusplus/IPv6Layer.h>


/*
Example
Flow Json Rule Struct

{
    "id": "tcp-handshake-detect",
    "description": "Detects normal TCP 3-way handshake sequence",
    "severity": "info",

    "sequence": [
        {
            "index": "A",
            "condition": {
                "tcp": {
                    "flags": ["S"],
                    "src_port": "any",
                    "dst_port": "any"
                }
            }
        },
        {
            "index": "B",
            "condition": {
                "tcp": {
                    "flags": ["S", "A"],
                    "src_ip": "any",
                    "dst_ip": "any"
                }
            },
            "timestamp": {
                "nano": 2000000000
            }
        },
        {
            "index": "C",
            "condition": {
                "tcp": {
                    "flags": ["A"]
                }
            },
            "timestamp": {
                "nano": 2000000000
            },
            "action": {
                "type": "notice",
                "message": "TCP 3-way handshake completed"
            }
        }
    ]
}


*/

namespace NDR
{
    namespace Sensor
    {
        namespace FlowRule
        {
            namespace RuleDef
            {
                namespace Direction
                {
                    constexpr const char* Ingoing = "in";
                    constexpr const char* Outgoing = "out";
                }
                // ---------------------------
                // 공통 문자열 상수
                // 지원하는 프로토콜
                // ---------------------------
                namespace ProtocolKey
                {
                    constexpr const char* ETHERNET = "ethernet";
                    constexpr const char* IP       = "ip";
                    constexpr const char* TCP      = "tcp";
                    constexpr const char* UDP      = "udp";
                    constexpr const char* ICMP     = "icmp";
                    constexpr const char* ARP      = "arp";
                    constexpr const char* DNS      = "dns";
                    constexpr const char* HTTP     = "http";
                    constexpr const char* TLS      = "tls";
                    constexpr const char* PAYLOAD      = "payload"; // 해석되지 못한 데이터 바이너리들
                }
                // ---------------------------
                // 프로토콜별 필드 정의
                // ---------------------------

                static const std::unordered_map<std::string, std::vector<std::string>> ProtocolFieldMap = {
                    // Ethernet (L2)
                    {
                        ProtocolKey::ETHERNET,
                        {"src", "dst", "type"}
                    },
                    // IP (L3)
                    {
                        ProtocolKey::IP,
                        {"version", "src_ip", "dst_ip", "protocol", "ttl", "tos", "length", "id", "flags", "fragment_offset"}
                    },
                    // TCP (L4)
                    {
                        ProtocolKey::TCP,
                        {"src_port", "dst_port", "flags", "seq", "ack", "window", "payload_size", "options"}
                    },
                    // UDP (L4)
                    {
                        ProtocolKey::UDP,
                        {"src_port", "dst_port", "length", "payload_size"}
                    },
                    // ICMP
                    {
                        ProtocolKey::ICMP,
                        {"type", "code", "id", "seq"}
                    },
                    // ARP
                    {
                        ProtocolKey::ARP,
                        {"opcode", "src_ip", "src_mac", "dst_ip", "dst_mac"}
                    },
                    // DNS
                    {
                        ProtocolKey::DNS,
                        {"opcode", "query_name", "query_name_contains", "query_type", "query_class", "is_response", "response_code", "answer_count", "answer_name", "answer_type", "answer_data", "answer_data_contains", "ttl", "domain_suffix", "domain_prefix", "length_query_name", "entropy_query_name"}
                    },
                    // HTTP
                    {
                        ProtocolKey::HTTP,
                        {
                            "request_method", "request_uri", "request_uri_contains", "request_header", "request_body_contains",
                            "response_status_code", "response_reason_phrase", "response_content_type", "response_server", "response_set_cookie", "response_header", "response_body_contains"
                        }
                    },
                    // TLS
                    {
                        ProtocolKey::TLS,
                        {"version", "handshake_type", "sni", "cipher_suites"}
                    },
                    // PAYLOAD ( None-Parsed Layer )
                    {
                        ProtocolKey::PAYLOAD,
                        {
                           /*
                                A - 사용예시 (페이로드 크기가 500바이트보다 크고, "evil" 문자열(hex: 6576696c)을 포함하는 패킷)
                                "payload": [
                                    { "size": 500, "size_match_method": ">" },
                                    { "binary": "6576696c" }
                                ]

                                B - 사용예시 (페이로드 크기가 64바이트가 아니고, 오프셋 8에서 1A2B3C 패턴이 나타나는 패킷)
                                "payload": [
                                    { "size": 64, "size_match_method": "!=" },
                                    { "binary": "1A2B3C", "offset": 8 }
                                ]
                                
                                C - 사용예시 (페이로드에 "powershell" 문자열이 포함된 패킷)
                                "payload": [ { "string": "powershell" } ]

                                D - 사용예시 (리눅스 명령어 매치)
                                "payload": [ { "regex": "(ls|cat|rm|cp|wget|curl)\\s+-[a-zA-Z0-9]" } ]

                                E - 사용예시 (인젝션 매치)
                                "payload": [
                                    { "size": 100, "size_match_method": ">=" },
                                    { "regex": "('|\"|;|--|\\/\\*).*?(UNION|SELECT|INSERT|UPDATE|DELETE)" }
                                ]
                           */
                            "size",
                            "size_match_method", 
                            "binary",
                            "offset",
                            "string",
                            "regex"
                        }
                    }
                };

                namespace ConditionLogic
                {
                    class ConditionObjectBase
                    {
                        public:
                            ConditionObjectBase() = default;
                            virtual ~ConditionObjectBase() = default;
                            virtual bool Match(const pcpp::Packet& pkt) = 0;
                    };

                    /*
                        PAYLOAD (None-Parsed L4+ Data) - Supports "binary", "string", and "regex"
                    */
                    class ConditionPayloadObject : public ConditionObjectBase
                    {
                    private:
                        enum class SizeMatchMethod { EQ, GT, LT, GTE, LTE, NE };

                        struct PayloadCondition {
                            std::optional<size_t> size;
                            SizeMatchMethod method = SizeMatchMethod::EQ;
                            std::optional<std::vector<uint8_t>> binary_pattern;
                            std::optional<std::regex> regex_pattern;
                            std::optional<size_t> offset;
                        };

                        std::vector<PayloadCondition> conditions;

                    public:
                        explicit ConditionPayloadObject(const json& payloadCond)
                        {
                            if (!payloadCond.is_array())
                            {
                                std::cerr << "[ERROR] Payload condition must be an array of objects." << std::endl;
                                return;
                            }
                            for (const auto& cond_item : payloadCond)
                            {
                                if (!cond_item.is_object()) continue;

                                PayloadCondition p_cond;

                                // 1. size 및 size_match_method 파싱
                                if (cond_item.contains("size") && cond_item["size"].is_number())
                                {
                                    p_cond.size = cond_item["size"].get<size_t>();
                                    if (cond_item.contains("size_match_method") && cond_item["size_match_method"].is_string())
                                    {
                                        std::string method_str = cond_item["size_match_method"].get<std::string>();
                                        if (method_str == "==") p_cond.method = SizeMatchMethod::EQ;
                                        else if (method_str == ">") p_cond.method = SizeMatchMethod::GT;
                                        else if (method_str == "<") p_cond.method = SizeMatchMethod::LT;
                                        else if (method_str == ">=") p_cond.method = SizeMatchMethod::GTE;
                                        else if (method_str == "<=") p_cond.method = SizeMatchMethod::LTE;
                                        else if (method_str == "!=") p_cond.method = SizeMatchMethod::NE;
                                        else std::cerr << "[WARN] Unknown size_match_method: " << method_str << ". Defaulting to '=='." << std::endl;
                                    }
                                }

                                // 2. 콘텐츠 매칭 키 파싱 (binary > string > regex 우선순위)
                                if (cond_item.contains("binary") && cond_item["binary"].is_string())
                                {
                                    p_cond.binary_pattern = hex_string_to_bytes(cond_item["binary"].get<std::string>());
                                }
                                else if (cond_item.contains("string") && cond_item["string"].is_string())
                                {
                                    std::string str_pattern = cond_item["string"].get<std::string>();
                                    p_cond.binary_pattern.emplace(str_pattern.begin(), str_pattern.end());
                                }
                                else if (cond_item.contains("regex") && cond_item["regex"].is_string())
                                {
                                    try {
                                        p_cond.regex_pattern.emplace(cond_item["regex"].get<std::string>());
                                    } catch (const std::regex_error& e) {
                                        std::cerr << "[ERROR] Invalid regex pattern: '" << cond_item["regex"].get<std::string>()
                                                << "'. Error: " << e.what() << std::endl;
                                    }
                                }

                                // 3. offset 파싱
                                if (cond_item.contains("offset") && cond_item["offset"].is_number())
                                {
                                    p_cond.offset = cond_item["offset"].get<size_t>();
                                }

                                conditions.push_back(p_cond);
                            }
                        }

                        bool Match(const pcpp::Packet& pkt) override
                        {
                            
                            const uint8_t* payload_data = nullptr;
                            size_t payload_len = 0;
                            pcpp::Layer* payloadContainer = pkt.getLayerOfType<pcpp::TcpLayer>() ? pkt.getLayerOfType<pcpp::TcpLayer>() :
                                                        pkt.getLayerOfType<pcpp::UdpLayer>() ? pkt.getLayerOfType<pcpp::UdpLayer>() :
                                                        pkt.getLayerOfType<pcpp::IcmpLayer>() ? pkt.getLayerOfType<pcpp::IcmpLayer>() :
                                                        pkt.getLayerOfType<pcpp::IPv6Layer>() ? pkt.getLayerOfType<pcpp::IPv6Layer>() :
                                                        static_cast<pcpp::Layer*>(pkt.getLayerOfType<pcpp::IPv4Layer>());
                            if (payloadContainer) {
                                
                                payload_data = payloadContainer->getLayerPayload();
                                payload_len = payloadContainer->getLayerPayloadSize();
                            }
                            
                            for (const auto& p_cond : conditions)
                            {
                                if (p_cond.size.has_value())
                                {
                                    bool size_ok = false;
                                    switch (p_cond.method)
                                    {
                                        case SizeMatchMethod::EQ:  size_ok = (payload_len == p_cond.size.value()); break;
                                        case SizeMatchMethod::GT:  size_ok = (payload_len >  p_cond.size.value()); break;
                                        case SizeMatchMethod::LT:  size_ok = (payload_len <  p_cond.size.value()); break;
                                        case SizeMatchMethod::GTE: size_ok = (payload_len >= p_cond.size.value()); break;
                                        case SizeMatchMethod::LTE: size_ok = (payload_len <= p_cond.size.value()); break;
                                        case SizeMatchMethod::NE:  size_ok = (payload_len != p_cond.size.value()); break;
                                    }
                                    if (!size_ok) return false;
                                }

                                // [FIX] Offset logic moved here to apply to both binary and regex matching
                                const uint8_t* search_start = payload_data;
                                size_t search_len = payload_len;

                                if (p_cond.offset.has_value())
                                {
                                    size_t offset = p_cond.offset.value();
                                    if (offset >= payload_len) return false; // Offset is out of bounds
                                    search_start += offset;
                                    search_len -= offset;
                                }

                                if (p_cond.binary_pattern.has_value())
                                {
                                    if (payloadContainer->getProtocol() == 4)
                                    {   
                                        pcpp::TcpLayer* tcp = (pcpp::TcpLayer*)payloadContainer;
                                        if( ntohs(tcp->getTcpHeader()->portDst) == 53 )
                                        {
                                            std::cout << "\nTELNET ~!!!!@!@!@!@!@!!@V\n" << std::string(p_cond.binary_pattern.value().begin(), p_cond.binary_pattern.value().end() ) << std::endl;
                                        }

                                    }
                                    const auto& pattern = p_cond.binary_pattern.value();
                                    if (pattern.empty() || search_len == 0 || pattern.size() > search_len) return false;

                                    if (p_cond.offset.has_value())
                                    {
                                        if (std::memcmp(search_start, pattern.data(), pattern.size()) != 0) return false;
                                    }
                                    else
                                    {
                                        auto it = std::search(search_start, search_start + search_len, pattern.begin(), pattern.end());
                                        if (it == (search_start + search_len)) return false;
                                    }
                                }
                                else if (p_cond.regex_pattern.has_value())
                                {
                                    if (search_len == 0) return false;
                                    
                                    if (!std::regex_search(
                                            reinterpret_cast<const char*>(search_start),
                                            reinterpret_cast<const char*>(search_start + search_len),
                                            p_cond.regex_pattern.value()))
                                    {
                                        return false;
                                    }
                                }
                            }
                            return true;
                        }

                    private:
                        static std::vector<uint8_t> hex_string_to_bytes(const std::string& hex)
                        {
                            std::vector<uint8_t> bytes;
                            if (hex.length() % 2 != 0) {
                                std::cerr << "[WARN] Hex string has odd length: " << hex << std::endl;
                                return bytes;
                            }
                            for (unsigned int i = 0; i < hex.length(); i += 2) {
                                try {
                                    bytes.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
                                } catch (const std::exception& e) {
                                    std::cerr << "[ERROR] Invalid hex character in string: " << hex << " (" << e.what() << ")" << std::endl;
                                    bytes.clear();
                                    return bytes;
                                }
                            }
                            return bytes;
                        }
                    };

                    /*
                        HTTP (헤더 순회 방식으로 수정)
                    */
                    class ConditionHTTPObject : public ConditionObjectBase
                    {
                    public:
                        explicit ConditionHTTPObject(const json& httpCond)
                        {
                            for (auto& [k, v] : httpCond.items())
                            {
                                // --- Request Fields ---
                                if (k == "request_method") request_method = v.get<std::string>();
                                else if (k == "request_uri") request_uri = v.get<std::string>();
                                else if (k == "request_uri_contains") request_uri_contains = v.get<std::string>();
                                else if (k == "request_header" && v.is_object())
                                    request_header = v.get<std::unordered_map<std::string, std::string>>();
                                else if (k == "request_body_contains") request_body_contains = v.get<std::string>();

                                // --- Response Fields ---
                                else if (k == "response_status_code") response_status_code = v.get<int>();
                                else if (k == "response_reason_phrase") response_reason_phrase = v.get<std::string>();
                                else if (k == "response_content_type") response_content_type = v.get<std::string>();
                                else if (k == "response_server") response_server = v.get<std::string>();
                                else if (k == "response_set_cookie") response_set_cookie_contains = v.get<std::string>();
                                else if (k == "response_header" && v.is_object())
                                    response_header = v.get<std::unordered_map<std::string, std::string>>();
                                else if (k == "response_body_contains") response_body_contains = v.get<std::string>();

                                else
                                    std::cerr << "[WARN] Unknown or malformed HTTP condition field: " << k << std::endl;
                            }
                        }

                        bool Match(const pcpp::Packet& pkt) override
                        {
                            
                            if (pcpp::HttpRequestLayer* req = pkt.getLayerOfType<pcpp::HttpRequestLayer>())
                            {
                                return MatchRequest(req);
                            }
                            else if (pcpp::HttpResponseLayer* res = pkt.getLayerOfType<pcpp::HttpResponseLayer>())
                            {
                                return MatchResponse(res);
                            }
                            return false;
                        }

                    private:
                        pcpp::HeaderField* findHeader(pcpp::HttpMessage* msg, const std::string& fieldName)
                        {
                            for (pcpp::HeaderField* curField = msg->getFirstField(); curField != nullptr; curField = msg->getNextField(curField))
                            {
                                if (iequals(curField->getFieldName(), fieldName))
                                {
                                    return curField;
                                }
                            }
                            return nullptr;
                        }

                        bool MatchRequest(pcpp::HttpRequestLayer* req)
                        {
                            pcpp::HttpRequestFirstLine* firstLine = req->getFirstLine();
                            if (!firstLine || !firstLine->isComplete()) return false;

                            if (request_method.has_value())
                            {
                                std::string methodStr;
                                switch(firstLine->getMethod())
                                {
                                    case pcpp::HttpRequestLayer::HttpGET: methodStr = "GET"; break;
                                    case pcpp::HttpRequestLayer::HttpPOST: methodStr = "POST"; break;
                                    case pcpp::HttpRequestLayer::HttpHEAD: methodStr = "HEAD"; break;
                                    case pcpp::HttpRequestLayer::HttpPUT: methodStr = "PUT"; break;
                                    case pcpp::HttpRequestLayer::HttpDELETE: methodStr = "DELETE"; break;
                                    case pcpp::HttpRequestLayer::HttpTRACE: methodStr = "TRACE"; break;
                                    case pcpp::HttpRequestLayer::HttpOPTIONS: methodStr = "OPTIONS"; break;
                                    case pcpp::HttpRequestLayer::HttpCONNECT: methodStr = "CONNECT"; break;
                                    case pcpp::HttpRequestLayer::HttpPATCH: methodStr = "PATCH"; break;
                                    default: methodStr = "Unknown";
                                }
                                if (!iequals(methodStr, request_method.value()))
                                    return false;
                            }
                            
                            if (request_uri.has_value() && firstLine->getUri() != request_uri.value())
                                return false;
                            
                            if (request_uri_contains.has_value() && firstLine->getUri().find(request_uri_contains.value()) == std::string::npos)
                                return false;

                            if (request_header.has_value())
                            {
                                for (const auto& [key, val] : request_header.value())
                                {
                                    pcpp::HeaderField* field = findHeader(req, key);
                                    if (!field || !iequals(field->getFieldValue(), val)) return false;
                                }
                            }

                            if (request_body_contains.has_value())
                            {
                                std::string body(reinterpret_cast<const char*>(req->getLayerPayload()), req->getLayerPayloadSize());
                                if (body.find(request_body_contains.value()) == std::string::npos) return false;
                            }
                            return true;
                        }

                        bool MatchResponse(pcpp::HttpResponseLayer* res)
                        {
                            pcpp::HttpResponseFirstLine* firstLine = res->getFirstLine();
                            if (!firstLine || !firstLine->isComplete()) return false;

                            if (response_status_code.has_value() && firstLine->getStatusCodeAsInt() != response_status_code.value())
                                return false;

                            if (response_reason_phrase.has_value() && !iequals(firstLine->getStatusCodeString(), response_reason_phrase.value()))
                                return false;
                            
                            if (response_content_type.has_value())
                            {
                                pcpp::HeaderField* field = findHeader(res, PCPP_HTTP_CONTENT_TYPE_FIELD);
                                if (!field || field->getFieldValue().find(response_content_type.value()) == std::string::npos) return false;
                            }
                            if (response_server.has_value())
                            {
                                pcpp::HeaderField* field = findHeader(res, PCPP_HTTP_SERVER_FIELD);
                                if (!field || field->getFieldValue().find(response_server.value()) == std::string::npos) return false;
                            }
                            if (response_set_cookie_contains.has_value())
                            {
                                pcpp::HeaderField* field = findHeader(res, "Set-Cookie");
                                if (!field || field->getFieldValue().find(response_set_cookie_contains.value()) == std::string::npos) return false;
                            }
                            if (response_header.has_value())
                            {
                                for (const auto& [key, val] : response_header.value())
                                {
                                    pcpp::HeaderField* field = findHeader(res, key);
                                    if (!field || !iequals(field->getFieldValue(), val)) return false;
                                }
                            }
                            if (response_body_contains.has_value())
                            {
                                std::string body(reinterpret_cast<const char*>(res->getLayerPayload()), res->getLayerPayloadSize());
                                if (body.find(response_body_contains.value()) == std::string::npos) return false;
                            }
                            return true;
                        }

                        static bool iequals(const std::string& a, const std::string& b)
                        {
                            return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return tolower(a) == tolower(b); });
                        }
                        
                        std::optional<std::string> request_method;
                        std::optional<std::string> request_uri;
                        std::optional<std::string> request_uri_contains;
                        std::optional<std::unordered_map<std::string, std::string>> request_header;
                        std::optional<std::string> request_body_contains;

                        std::optional<int> response_status_code;
                        std::optional<std::string> response_reason_phrase;
                        std::optional<std::string> response_content_type;
                        std::optional<std::string> response_server;
                        std::optional<std::string> response_set_cookie_contains;
                        std::optional<std::unordered_map<std::string, std::string>> response_header;
                        std::optional<std::string> response_body_contains;
                    };
                    
                    /*
                        TLS (PcapPlusPlus API에 맞게 최종 수정)
                    */
                    class ConditionTLSObject : public ConditionObjectBase
                    {
                    public:
                        explicit ConditionTLSObject(const json& tlsCond)
                        {
                            for (auto& [k, v] : tlsCond.items())
                            {
                                if (k == "version") version = v.get<std::string>();
                                else if (k == "handshake_type") handshake_type = v.get<std::string>();
                                else if (k == "sni") sni = v.get<std::string>();
                                else if (k == "cipher_suites") cipher_suites = v.get<std::vector<std::string>>();
                                else
                                    std::cerr << "[WARN] Unknown TLS condition field: " << k << std::endl;
                            }
                        }

                        bool Match(const pcpp::Packet& pkt) override
                        {
                            for (pcpp::Layer* currentLayer = pkt.getFirstLayer(); currentLayer != nullptr; currentLayer = currentLayer->getNextLayer())
                            {
                                pcpp::SSLHandshakeLayer* handshakeLayer = dynamic_cast<pcpp::SSLHandshakeLayer*>(currentLayer);
                                if (!handshakeLayer)
                                    continue;

                                for (size_t i = 0; i < handshakeLayer->getHandshakeMessagesCount(); ++i)
                                {
                                    pcpp::SSLHandshakeMessage* msg = handshakeLayer->getHandshakeMessageAt(i);
                                    if (!msg) continue;

                                    if (MatchMessage(msg))
                                    {
                                        return true;
                                    }
                                }
                            }
                            return false;
                        }

                    private:
                        bool MatchMessage(pcpp::SSLHandshakeMessage* msg)
                        {
                            if (handshake_type.has_value())
                            {
                                std::string msgTypeStr = handshakeTypeToString(msg->getHandshakeType());
                                if (!iequals(handshake_type.value(), msgTypeStr))
                                {
                                    return false;
                                }
                            }

                            if (pcpp::SSLClientHelloMessage* clientHello = dynamic_cast<pcpp::SSLClientHelloMessage*>(msg))
                            {
                                if (version.has_value())
                                {
                                    pcpp::SSLVersion versionObj = clientHello->getHandshakeVersion();
                                    if (!iequals(versionObj.toString(), version.value()))
                                        return false;
                                }
                                
                                if (cipher_suites.has_value())
                                {
                                    for (const auto& rule_suite_name : cipher_suites.value())
                                    {
                                        bool found = false;
                                        for (size_t j = 0; j < clientHello->getCipherSuiteCount(); ++j)
                                        {
                                            pcpp::SSLCipherSuite* pkt_suite = clientHello->getCipherSuite(j);
                                            if (pkt_suite)
                                            {
                                                std::string suiteName = pkt_suite->asString();
                                                if (iequals(suiteName, rule_suite_name))
                                                {
                                                    found = true;
                                                    break;
                                                }
                                            }
                                        }
                                        if (!found) return false;
                                    }
                                }
                                return true;
                            }

                            if (pcpp::SSLServerHelloMessage* serverHello = dynamic_cast<pcpp::SSLServerHelloMessage*>(msg))
                            {
                                if (version.has_value())
                                {
                                    pcpp::SSLVersion versionObj = serverHello->getHandshakeVersion();
                                    if (!iequals(versionObj.toString(), version.value()))
                                        return false;
                                }
                                
                                if (cipher_suites.has_value())
                                {
                                    pcpp::SSLCipherSuite* chosenSuite = serverHello->getCipherSuite();
                                    if (!chosenSuite) return false;

                                    std::string chosenSuiteName = chosenSuite->asString();
                                    bool found = false;
                                    for (const auto& rule_suite_name : cipher_suites.value())
                                    {
                                        if (iequals(chosenSuiteName, rule_suite_name))
                                        {
                                            found = true;
                                            break;
                                        }
                                    }
                                    if (!found) return false;
                                }
                                return true;
                            }
                            
                            if (handshake_type.has_value() && !sni.has_value() && !version.has_value() && !cipher_suites.has_value())
                            {
                                return true;
                            }

                            return false;
                        }

                        static std::string handshakeTypeToString(pcpp::SSLHandshakeType type)
                        {
                            switch (type)
                            {
                                case pcpp::SSL_CLIENT_HELLO: return "client_hello";
                                case pcpp::SSL_SERVER_HELLO: return "server_hello";
                                case pcpp::SSL_CERTIFICATE: return "certificate";
                                case pcpp::SSL_SERVER_KEY_EXCHANGE: return "server_key_exchange";
                                case pcpp::SSL_CERTIFICATE_REQUEST: return "certificate_request";
                                case pcpp::SSL_SERVER_DONE: return "server_hello_done";
                                case pcpp::SSL_CERTIFICATE_VERIFY: return "certificate_verify";
                                case pcpp::SSL_CLIENT_KEY_EXCHANGE: return "client_key_exchange";
                                case pcpp::SSL_FINISHED: return "finished";
                                case pcpp::SSL_NEW_SESSION_TICKET: return "new_session_ticket";
                                default: return "unknown";
                            }
                        }

                        static bool iequals(const std::string& a, const std::string& b)
                        {
                            return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return tolower(a) == tolower(b); });
                        }

                        std::optional<std::string> version;
                        std::optional<std::string> handshake_type;
                        std::optional<std::string> sni;
                        std::optional<std::vector<std::string>> cipher_suites;
                    };

                    /*
                        DNS
                    */
                    class ConditionDNSObject : public ConditionObjectBase
                    {
                    public:
                        explicit ConditionDNSObject(const json& dnsCond)
                        {
                            for (auto& [k, v] : dnsCond.items())
                            {
                                if (k == "opcode") opcode = v.get<uint8_t>();
                                else if (k == "is_response") is_response = v.get<bool>();
                                else if (k == "query_name") query_name = v.get<std::string>();
                                else if (k == "query_name_contains") query_name_contains = v.get<std::string>();
                                else if (k == "query_type") query_type = v.get<std::string>();
                                else if (k == "answer_name") answer_name = v.get<std::string>();
                                else if (k == "answer_type") answer_type = v.get<std::string>();
                                else if (k == "answer_data_contains") answer_data_contains = v.get<std::string>();
                                else if (k == "response_code") response_code = v.get<uint8_t>();
                                else if (k == "ttl") ttl = v.get<uint32_t>();
                                else if (k == "domain_suffix") domain_suffix = v.get<std::string>();
                                else if (k == "domain_prefix") domain_prefix = v.get<std::string>();
                                else if (k == "entropy_query_name") entropy_query_name = v.get<double>();
                                else
                                    std::cerr << "[WARN] Unknown DNS condition field: " << k << std::endl;
                            }
                        }

                        bool Match(const pcpp::Packet& pkt) override
                        {
                            pcpp::DnsLayer* dns = pkt.getLayerOfType<pcpp::DnsLayer>();
                            if (!dns)
                                return false;

                            if (opcode.has_value() && dns->getDnsHeader()->opcode != opcode.value())
                                return false;
                            if (is_response.has_value())
                            {
                                bool pktIsResp = dns->getDnsHeader()->queryOrResponse != 0;
                                if (pktIsResp != is_response.value())
                                    return false;
                            }
                            if (response_code.has_value() && dns->getDnsHeader()->responseCode != response_code.value())
                                return false;
                            
                            if (query_name.has_value() || query_name_contains.has_value() || domain_suffix.has_value() || domain_prefix.has_value() ||
                                entropy_query_name.has_value() || query_type.has_value())
                            {
                                bool matchFound = false;
                                for (pcpp::DnsQuery* q = dns->getFirstQuery(); q != nullptr; q = dns->getNextQuery(q))
                                {
                                    std::string qname = q->getName();
                                    if (query_name.has_value() && qname != query_name.value()) continue;
                                    if (query_name_contains.has_value() && qname.find(query_name_contains.value()) == std::string::npos) continue;
                                    if (domain_prefix.has_value() && qname.rfind(domain_prefix.value(), 0) != 0) continue;
                                    if (domain_suffix.has_value() && !ends_with(qname, domain_suffix.value())) continue;

                                    if (entropy_query_name.has_value())
                                    {
                                        double e = calc_entropy(qname);
                                        if (e < entropy_query_name.value()) continue;
                                    }
                                    if (query_type.has_value())
                                    {
                                        std::string typeStr = dnsTypeToStr(q->getDnsType());
                                        if (!iequals(typeStr, query_type.value())) continue;
                                    }
                                    matchFound = true;
                                    break;
                                }
                                if (!matchFound)
                                    return false;
                            }

                            if (answer_name.has_value() || answer_type.has_value() || answer_data_contains.has_value() || ttl.has_value())
                            {
                                bool matchFound = false;
                                for (pcpp::DnsResource* a = dns->getFirstAnswer(); a != nullptr; a = dns->getNextAnswer(a))
                                {
                                    if (answer_name.has_value() && a->getName() != answer_name.value())
                                        continue;
                                    if (answer_type.has_value())
                                    {
                                        std::string typeStr = dnsTypeToStr(a->getDnsType());
                                        if (!iequals(typeStr, answer_type.value()))
                                            continue;
                                    }
                                    if (ttl.has_value() && a->getTTL() != ttl.value())
                                        continue;
                                    
                                    auto dataPtr = a->getData();
                                    std::string dataStr = dataPtr ? dataPtr->toString() : "";
                                    if (answer_data_contains.has_value() && dataStr.find(answer_data_contains.value()) == std::string::npos)
                                        continue;

                                    matchFound = true;
                                    break;
                                }
                                if (!matchFound)
                                    return false;
                            }
                            return true;
                        }

                    private:
                        std::optional<uint8_t> opcode;
                        std::optional<bool> is_response;
                        std::optional<std::string> query_name, query_name_contains, query_type;
                        std::optional<std::string> answer_name, answer_type, answer_data_contains;
                        std::optional<uint8_t> response_code;
                        std::optional<uint32_t> ttl;
                        std::optional<std::string> domain_suffix, domain_prefix;
                        std::optional<double> entropy_query_name;

                        static bool iequals(const std::string& a, const std::string& b) { return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return tolower(a) == tolower(b); }); }
                        static bool ends_with(const std::string& s, const std::string& suffix) { if (s.size() < suffix.size()) return false; return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0; }
                        static double calc_entropy(const std::string& str) { if (str.empty()) return 0.0; std::array<size_t, 256> freq{}; for (unsigned char c : str) ++freq[c]; double len = static_cast<double>(str.size()); double entropy = 0.0; for (size_t f : freq) { if (!f) continue; double p = f / len; entropy -= p * std::log2(p); } return entropy; }
                        static std::string dnsTypeToStr(pcpp::DnsType type) { switch (type) { case pcpp::DNS_TYPE_A: return "A"; case pcpp::DNS_TYPE_AAAA: return "AAAA"; case pcpp::DNS_TYPE_CNAME: return "CNAME"; case pcpp::DNS_TYPE_PTR: return "PTR"; case pcpp::DNS_TYPE_MX: return "MX"; case pcpp::DNS_TYPE_TXT: return "TXT"; case pcpp::DNS_TYPE_SRV: return "SRV"; default: return std::to_string(type); } }
                    };

                    /*
                        ICMP
                    */
                    class ConditionICMPObject : public ConditionObjectBase
                    {
                    public:
                        ConditionICMPObject(const json& icmpCond)
                        {
                            for (auto& [k, v] : icmpCond.items())
                            {
                                if (k == "type") type = v.get<unsigned int>();
                                else if (k == "code") code = v.get<unsigned int>();
                            }
                        }
                        bool Match(const pcpp::Packet& pkt) override
                        {
                            pcpp::IcmpLayer* icmp = pkt.getLayerOfType<pcpp::IcmpLayer>();
                            if (!icmp) return false;
                            pcpp::icmphdr* hdr = icmp->getIcmpHeader();
                            if (type && hdr->type != *type) return false;
                            if (code && hdr->code != *code) return false;
                            return true;
                        }
                    private:
                        std::optional<unsigned int> type, code, id, seq;
                    };

                    /*
                        ARP
                    */
                    class ConditionARPObject : public ConditionObjectBase
                    {
                    public:
                        ConditionARPObject(const json& arpCond)
                        {
                            for (auto& [k, v] : arpCond.items())
                            {
                                if (k == "opcode") opcode = v.get<unsigned int>();
                                else if (k == "src_ip") src_ip = v.get<std::string>();
                                else if (k == "dst_ip") dst_ip = v.get<std::string>();
                                else if (k == "src_mac") src_mac = v.get<std::string>();
                                else if (k == "dst_mac") dst_mac = v.get<std::string>();
                            }
                        }
                        bool Match(const pcpp::Packet& pkt) override
                        {
                            pcpp::ArpLayer* arp = pkt.getLayerOfType<pcpp::ArpLayer>();
                            if (!arp) return false;
                            if (opcode && ntohs(arp->getArpHeader()->opcode) != *opcode) return false;
                            if (src_ip && arp->getSenderIpAddr().toString() != *src_ip) return false;
                            if (dst_ip && arp->getTargetIpAddr().toString() != *dst_ip) return false;
                            if (src_mac && arp->getSenderMacAddress().toString() != *src_mac) return false;
                            if (dst_mac && arp->getTargetMacAddress().toString() != *dst_mac) return false;
                            return true;
                        }
                    private:
                        std::optional<unsigned int> opcode;
                        std::optional<std::string> src_ip, dst_ip, src_mac, dst_mac;
                    };

                    /*
                        IP
                    */
                    class ConditionIPObject : public ConditionObjectBase
                    {
                    public:
                        ConditionIPObject(const json& ipCond)
                        {
                            for (auto& [k, v] : ipCond.items())
                            {
                                if (k == "src_ip") src_ip = v.get<std::string>();
                                else if (k == "dst_ip") dst_ip = v.get<std::string>();
                                else if (k == "ttl") ttl = v.get<unsigned int>();
                                else if (k == "protocol") protocol = v.get<unsigned int>();
                                else if (k == "is_fragment") protocol = v.get<bool>();
                            }
                        }
                        bool Match(const pcpp::Packet& pkt) override
                        {
                            pcpp::IPv4Layer* ip = pkt.getLayerOfType<pcpp::IPv4Layer>();
                            
                            if (!ip) return false;
                            if (src_ip.has_value() && ip->getSrcIPAddress().toString() != *src_ip) return false;
                            if (dst_ip.has_value() && ip->getDstIPAddress().toString() != *dst_ip) return false;
                            if (ttl.has_value() && ip->getIPv4Header()->timeToLive != *ttl) return false;
                            if (protocol.has_value() && ip->getIPv4Header()->protocol != *protocol) return false;
                            if (is_fragment.has_value() && ip->isFragment() != is_fragment.value()) return false;
                            return true;
                        }
                    private:
                        std::optional<std::string> src_ip, dst_ip;
                        std::optional<unsigned int> ttl, protocol;
                        std::optional<bool> is_fragment;
                    };

                    /*
                        ETHERNET
                    */
                    class ConditionEthernetObject : public ConditionObjectBase
                    {
                    public:
                        ConditionEthernetObject(const json& ethCond)
                        {
                            for (auto& [k, v] : ethCond.items())
                            {
                                if (k == "src" || k == "src_mac") src_mac = v.get<std::string>();
                                else if (k == "dst" || k == "dst_mac") dst_mac = v.get<std::string>();
                                else if (k == "type") ether_type = v.get<unsigned int>();
                            }
                        }
                        bool Match(const pcpp::Packet& pkt) override
                        {
                            pcpp::EthLayer* eth = pkt.getLayerOfType<pcpp::EthLayer>();
                            if (!eth) return false;
                            if (src_mac && eth->getSourceMac().toString() != *src_mac) return false;
                            if (dst_mac && eth->getDestMac().toString() != *dst_mac) return false;
                            if (ether_type && ntohs(eth->getEthHeader()->etherType) != *ether_type) return false;
                            return true;
                        }
                    private:
                        std::optional<std::string> src_mac, dst_mac;
                        std::optional<unsigned int> ether_type;
                    };

                    /*
                        UDP
                    */
                    class ConditionUDPObject : public ConditionObjectBase
                    {
                    public:
                        ConditionUDPObject(const json& UDP_Condition)
                        {
                            for (auto& [field, value] : UDP_Condition.items())
                            {
                                if (field == "src_port" || field == "source_port") _set_source_port(value);
                                else if (field == "dst_port" || field == "destination_port") _set_destination_port(value);
                                else if (field == "payload_size" || field == "length") _set_payload_size(value);
                                else std::cerr << "[WARN] UDP Condition: unknown field '" << field << "'" << std::endl;
                            }
                        }

                        bool Match(const pcpp::Packet& pkt) override
                        {
                            pcpp::UdpLayer* udpLayer = pkt.getLayerOfType<pcpp::UdpLayer>();
                            if (!udpLayer) return false;
                            pcpp::udphdr* udpHeader = udpLayer->getUdpHeader();
                            if (source_port.has_value() && source_port.value() != ANY_PORT && ntohs(udpHeader->portSrc) != source_port.value()) return false;
                            if (destination_port.has_value() && destination_port.value() != ANY_PORT && ntohs(udpHeader->portDst) != destination_port.value()) return false;
                            if (payload_size.has_value() && udpLayer->getLayerPayloadSize() != payload_size.value()) return false;
                            return true;
                        }

                    private:
                        static constexpr unsigned long ANY_PORT = 0xFFFFFFFF;
                        std::optional<unsigned long> source_port, destination_port;
                        std::optional<size_t> payload_size;
                        void _set_source_port(const json& val) { if (val.is_string() && val.get<std::string>() == "any") source_port = ANY_PORT; else source_port = val.get<unsigned long>(); }
                        void _set_destination_port(const json& val) { if (val.is_string() && val.get<std::string>() == "any") destination_port = ANY_PORT; else destination_port = val.get<unsigned long>(); }
                        void _set_payload_size(const json& val) { if (val.is_number_unsigned()) payload_size = val.get<size_t>(); else if (val.is_string() && val.get<std::string>() == "any") payload_size.reset(); }
                    };

                    /*
                        TCP
                    */
                    class ConditionTCPObject : public ConditionObjectBase
                    {
                    public:
                        ConditionTCPObject(const json& TCP_Condition)
                        {
                            for (auto& [field, value] : TCP_Condition.items())
                            {
                                if (field == "flags") _set_flags(value.get<std::vector<std::string>>());
                                else if (field == "src_port" || field == "source_port") _set_source_port(value);
                                else if (field == "dst_port" || field == "destination_port") _set_destination_port(value);
                                else if (field == "payload_size") _set_payload_size(value);
                                else std::cerr << "[WARN] TCP Condition: unknown field '" << field << "'" << std::endl;
                            }
                        }

                        bool Match(const pcpp::Packet& pkt) override
                        {
                            pcpp::TcpLayer* tcpLayer = pkt.getLayerOfType<pcpp::TcpLayer>();
                            if (!tcpLayer) return false;
                            pcpp::tcphdr* tcpHeader = tcpLayer->getTcpHeader();

                            if (source_port.has_value() && source_port.value() != ANY_PORT && ntohs(tcpHeader->portSrc) != source_port.value()) return false;
                            if (destination_port.has_value() && destination_port.value() != ANY_PORT && ntohs(tcpHeader->portDst) != destination_port.value()) return false;

                            if (flags.has_value())
                            {
                                bool expect_syn = false, expect_ack = false, expect_fin = false, 
                                expect_rst = false, expect_psh = false, expect_urg = false, expect_null = false;

                                for(const auto& flag : flags.value())
                                {
                                    switch (flag)
                                    {
                                        case SYN: expect_syn = true; break;
                                        case ACK: expect_ack = true; break;
                                        case FIN: expect_fin = true; break;
                                        case RST: expect_rst = true; break;
                                        case PSH: expect_psh = true; break;
                                        case URG: expect_urg = true; break;
                                        case None: expect_null = true; break;
                                        default: break; // [IMPROVEMENT] ECE, CWR are ignored for matching
                                    }
                                }

                                if (((bool)tcpHeader->synFlag) != expect_syn ||
                                    ((bool)tcpHeader->ackFlag) != expect_ack ||
                                    ((bool)tcpHeader->finFlag) != expect_fin ||
                                    ((bool)tcpHeader->rstFlag) != expect_rst ||
                                    ((bool)tcpHeader->pshFlag) != expect_psh ||
                                    ((bool)tcpHeader->urgFlag) != expect_urg ||
                                    ( !tcpHeader->synFlag && !tcpHeader->ackFlag && !tcpHeader->finFlag && !tcpHeader->rstFlag && !tcpHeader->pshFlag && !tcpHeader->urgFlag ) != expect_null )
                                {
                                    return false;
                                }
                            }
                            
                            if (payload_size.has_value() && tcpLayer->getLayerPayloadSize() != payload_size.value()) return false;

                            return true;
                        }

                    private:
                        static constexpr unsigned long ANY_PORT = 0xFFFFFFFF;
                        std::optional<unsigned long> destination_port, source_port;
                        std::optional<size_t> payload_size;
                        enum TCPflagsEnum { SYN, ACK, RST, FIN, PSH, URG, ECE, CWR, None };
                        std::optional<std::vector<TCPflagsEnum>> flags;

                        void _set_flags(const std::vector<std::string>& flags_Vector) { 
                            std::vector<TCPflagsEnum> flags_; 
                            // [IMPROVEMENT] Use .empty() for clarity
                            if(flags_Vector.empty())
                            {
                                flags_.push_back(None);
                            }
                            else
                            {
                                for (auto& flag : flags_Vector) { 
                                    std::string f = flag; std::transform(f.begin(), f.end(), f.begin(), ::toupper); 
                                    if (f == "S" || f == "SYN") flags_.push_back(SYN); 
                                    else if (f == "A" || f == "ACK") flags_.push_back(ACK); 
                                    else if (f == "R" || f == "RST") flags_.push_back(RST); 
                                    else if (f == "F" || f == "FIN") flags_.push_back(FIN); 
                                    else if (f == "P" || f == "PSH") flags_.push_back(PSH); 
                                    else if (f == "U" || f == "URG") flags_.push_back(URG); 
                                    else if (f == "E" || f == "ECE") flags_.push_back(ECE); 
                                    else if (f == "C" || f == "CWR") flags_.push_back(CWR); 
                                    else throw std::runtime_error("Unknown TCP flag: " + flag); 
                                } 
                            }
                            flags = flags_; 
                        }
                        void _set_source_port(const json& val) { if (val.is_string() && val.get<std::string>() == "any") source_port = ANY_PORT; else source_port = val.get<unsigned long>(); }
                        void _set_destination_port(const json& val) { if (val.is_string() && val.get<std::string>() == "any") destination_port = ANY_PORT; else destination_port = val.get<unsigned long>(); }
                        void _set_payload_size(const json& val) { if (val.is_number_unsigned()) payload_size = val.get<size_t>(); }
                    };
                }
                
                class RuleConditionObject
                {
                public:
                    RuleConditionObject() = default;

                    bool InsertRule(const json& Object)
                    {
                        try
                        {
                            for (auto& [protocol, condObj] : Object.items())
                            {
                                if (protocol == ProtocolKey::ETHERNET)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionEthernetObject>(condObj));
                                else if (protocol == ProtocolKey::IP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionIPObject>(condObj));
                                else if (protocol == ProtocolKey::ARP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionARPObject>(condObj));
                                else if (protocol == ProtocolKey::DNS)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionDNSObject>(condObj));
                                else if (protocol == ProtocolKey::ICMP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionICMPObject>(condObj));
                                else if (protocol == ProtocolKey::HTTP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionHTTPObject>(condObj));
                                else if (protocol == ProtocolKey::TCP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionTCPObject>(condObj));
                                else if (protocol == ProtocolKey::UDP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionUDPObject>(condObj));
                                else if (protocol == ProtocolKey::TLS)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionTLSObject>(condObj));
                                else if (protocol == ProtocolKey::PAYLOAD)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionPayloadObject>(condObj));
                                else
                                {
                                    std::cerr << "[ERROR] Unsupported protocol condition: " << protocol << std::endl;
                                    return false;
                                }
                            }
                        }
                        catch (const std::exception& e)
                        {
                            std::cerr << "[ERROR] Failed to parse rule condition: " << e.what() << std::endl;
                            return false;
                        }
                        return true;
                    }

                    bool Match(const pcpp::Packet& pkt)
                    {
                        // [FIX] An empty condition should not match anything.
                        if (conditions.empty()) return false; 
                        
                        for (const auto& condition : conditions)
                        {
                            if (!condition->Match(pkt))
                                return false;
                            
                        }
                        return true;
                    }
                    
                private:
                    std::vector<std::unique_ptr<ConditionLogic::ConditionObjectBase>> conditions;
                };
            }
        }
    }
}

#endif