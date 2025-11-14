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

#include <pcapplusplus/FtpLayer.h>
#include <pcapplusplus/TelnetLayer.h>
#include <pcapplusplus/StpLayer.h>
#include <pcapplusplus/VlanLayer.h>
#include <pcapplusplus/SllLayer.h>         // Linux cooked capture
#include <pcapplusplus/NullLoopbackLayer.h>
#include <pcapplusplus/PacketTrailerLayer.h>
#include <pcapplusplus/PPPoELayer.h>
#include <pcapplusplus/VxlanLayer.h>
#include <pcapplusplus/MplsLayer.h>
#include <pcapplusplus/StpLayer.h>
#include <pcapplusplus/WakeOnLanLayer.h>
#include <pcapplusplus/GreLayer.h>
#include <pcapplusplus/IcmpV6Layer.h>
#include <pcapplusplus/NdpLayer.h>
#include <pcapplusplus/VrrpLayer.h>
#include <pcapplusplus/WireGuardLayer.h>
#include <pcapplusplus/CotpLayer.h>
#include <pcapplusplus/IPSecLayer.h>
#include <pcapplusplus/GtpLayer.h>
#include <pcapplusplus/TpktLayer.h>
#include <pcapplusplus/SdpLayer.h>
#include <pcapplusplus/SipLayer.h>
#include <pcapplusplus/DhcpLayer.h>
#include <pcapplusplus/DhcpV6Layer.h>
#include <pcapplusplus/FtpLayer.h>
#include <pcapplusplus/LdapLayer.h>
#include <pcapplusplus/NtpLayer.h>
#include <pcapplusplus/RadiusLayer.h>
#include <pcapplusplus/S7CommLayer.h>
#include <pcapplusplus/SmtpLayer.h>
#include <pcapplusplus/SomeIpLayer.h>
#include <pcapplusplus/TelnetLayer.h>
#include <pcapplusplus/NdpLayer.h>

#include <pcapplusplus/BgpLayer.h>

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
#include <pcapplusplus/PayloadLayer.h>
#include <pcapplusplus/SSHLayer.h>

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
                    constexpr const char* SSH      = "ssh"; 

                     constexpr const char* VLAN     = "vlan";
                    constexpr const char* SLL      = "sll";
                    constexpr const char* NULL_LOOPBACK = "null_loopback";
                    constexpr const char* PPPOE    = "pppoe";
                    constexpr const char* VXLAN    = "vxlan";
                    constexpr const char* MPLS     = "mpls";
                    constexpr const char* GRE      = "gre";
                    constexpr const char* ICMPV6   = "icmpv6";
                    constexpr const char* NDP      = "ndp";
                    constexpr const char* VRRP     = "vrrp";
                    constexpr const char* WIREGUARD= "wireguard";
                    constexpr const char* IPSEC    = "ipsec";
                    constexpr const char* GTP      = "gtp";
                    constexpr const char* SIP      = "sip";
                    constexpr const char* DHCP     = "dhcp";
                    constexpr const char* FTP      = "ftp";
                    constexpr const char* TELNET   = "telnet";
                    constexpr const char* NTP      = "ntp";
                    constexpr const char* SMTP     = "smtp";
                    constexpr const char* RADIUS   = "radius";
                    constexpr const char* LDAP     = "ldap";

                }
                // ---------------------------
                // 프로토콜별 필드 정의
                // ---------------------------

                static const std::unordered_map<std::string, std::vector<std::string>> ProtocolFieldMap = {
                     { ProtocolKey::ETHERNET, {"src", "dst", "type"}},
                    { ProtocolKey::IP, {"version", "src_ip", "dst_ip", "protocol", "ttl", "tos", "length", "id", "flags", "fragment_offset"}},
                    { ProtocolKey::TCP, {"src_port", "dst_port", "flags", "seq", "ack", "window", "payload_size", "options"}},
                    { ProtocolKey::UDP, {"src_port", "dst_port", "length", "payload_size"}},
                    { ProtocolKey::ICMP, {"type", "code", "id", "seq"}},
                    { ProtocolKey::ARP, {"opcode", "src_ip", "src_mac", "dst_ip", "dst_mac"}},
                    { ProtocolKey::DNS, {"opcode", "query_name", "query_name_contains", "query_type", "query_class", "is_response", "response_code", "answer_count", "answer_name", "answer_type", "answer_data", "answer_data_contains", "ttl", "domain_suffix", "domain_prefix", "length_query_name", "entropy_query_name"}},
                    { ProtocolKey::HTTP, {"request_method", "request_uri", "request_uri_contains", "request_header", "request_body_contains", "response_status_code", "response_reason_phrase", "response_content_type", "response_server", "response_set_cookie", "response_header", "response_body_contains"}},
                    { ProtocolKey::TLS, {"version", "handshake_type", "sni", "cipher_suites"}},
                    { ProtocolKey::SSH, { "type", "direction", "client_version", "server_version", "version_contains", "kex_algorithms_contains", "server_host_key_algorithms_contains", "encryption_algorithms_c2s_contains", "encryption_algorithms_s2c_contains", "mac_algorithms_c2s_contains", "mac_algorithms_s2c_contains" }},
                    { ProtocolKey::PAYLOAD, { "size", "size_match_method", "binary", "offset", "string", "regex" }},

                    // --- Newly Added Protocols ---
                    { ProtocolKey::VLAN, {"id", "priority", "dei"}},
                    { ProtocolKey::SLL, {"packet_type", "addr_type"}},
                    { ProtocolKey::NULL_LOOPBACK, {"protocol_type"}},
                    { ProtocolKey::PPPOE, {"type", "session_id", "code", "ppp_protocol"}},
                    { ProtocolKey::VXLAN, {"vni"}},
                    { ProtocolKey::MPLS, {"label", "ttl", "tc", "is_bottom_of_stack"}},
                    { ProtocolKey::GRE, {"version", "protocol_type", "seq_number", "ack_number"}},
                    { ProtocolKey::ICMPV6, {"type", "code"}},
                    { ProtocolKey::NDP, {"type", "target_address"}},
                    { ProtocolKey::VRRP, {"version", "type", "vrid"}},
                    { ProtocolKey::WIREGUARD, {"message_type", "sender_index", "receiver_index"}},
                    { ProtocolKey::IPSEC, {"type", "spi", "seq_number"}},
                    { ProtocolKey::GTP, {"version", "message_type", "teid"}},
                    { ProtocolKey::SIP, {"type", "method", "status_code", "uri_contains", "header_contains"}},
                    { ProtocolKey::DHCP, {"message_type", "op_code"}},
                    { ProtocolKey::FTP, {"type", "command", "status_code", "message_contains"}},
                    { ProtocolKey::TELNET, {"command", "data_contains"}},
                    { ProtocolKey::NTP, {"mode", "stratum", "leap_indicator"}},
                    { ProtocolKey::SMTP, {"command", "data_contains"}},
                    { ProtocolKey::RADIUS, {"code", "id"}},
                    { ProtocolKey::LDAP, {"op_code", "message_id"}}
                    /*
                    // PAYLOAD ( None-Parsed Layer )
                    {
                        ProtocolKey::PAYLOAD,
                        {
                           
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
                           
                            "size",
                            "size_match_method", 
                            "binary",
                            "offset",
                            "string",
                            "regex"
                        }
                    }*/
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
                            // --- 수정 시작 ---
                            // 이전의 페이로드 컨테이너 탐색 방식은 안정적이지 않았습니다.
                            // pcpp::Packet::getLayerPayload()는 파싱되지 못한 최상위 레이어의 페이로드를
                            // 가져오는 올바르고 안전한 방법입니다. "PAYLOAD" 조건이 검사해야 할 대상이 바로 이것입니다.

                            pcpp::PayloadLayer* payloadLayer = pkt.getLayerOfType<pcpp::PayloadLayer>();
                            if (payloadLayer == nullptr) {
                                return false;
                            }

                            const uint8_t* payload_data = payloadLayer->getPayload();
                            size_t payload_len = payloadLayer->getPayloadLen();

                            // 페이로드가 전혀 없는 경우, 내용 기반 규칙은 매칭될 수 없습니다.
                            if (payload_data == nullptr || payload_len == 0)
                            {
                                // 하지만 size: 0 과 같은 규칙은 매칭될 수 있으므로 확인해야 합니다.
                                // 내용(binary, string, regex)이나 0이 아닌 크기를 요구하는 규칙은 실패해야 합니다.
                                bool can_match_empty = true;
                                for (const auto& p_cond : conditions)
                                {
                                    if (p_cond.binary_pattern.has_value() || p_cond.regex_pattern.has_value()) {
                                        can_match_empty = false;
                                        break;
                                    }
                                    if (p_cond.size.has_value()) {
                                        // size 조건이 payload_len = 0으로 충족될 수 있는지 확인
                                        size_t rule_size = p_cond.size.value();
                                        switch (p_cond.method)
                                        {
                                            case SizeMatchMethod::EQ:  if (0 != rule_size) { can_match_empty = false; } break;
                                            case SizeMatchMethod::GT:  can_match_empty = false; break; // 0 > size 는 항상 거짓
                                            case SizeMatchMethod::LT:  if (0 >= rule_size) { can_match_empty = false; } break;
                                            case SizeMatchMethod::GTE: if (0 < rule_size)  { can_match_empty = false; } break;
                                            case SizeMatchMethod::LTE: /* 0 <= size 는 항상 참 */ break;
                                            case SizeMatchMethod::NE:  if (0 == rule_size) { can_match_empty = false; } break;
                                        }
                                        if (!can_match_empty) break;
                                    }
                                }
                                // size:0 과 같은 조건이 매칭될 때만 true를 반환
                                return can_match_empty;
                            }
                            // --- 수정 끝 ---

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

                                const uint8_t* search_start = payload_data;
                                size_t search_len = payload_len;

                                if (p_cond.offset.has_value())
                                {
                                    size_t offset = p_cond.offset.value();
                                    if (offset >= payload_len) return false;
                                    search_start += offset;
                                    search_len -= offset;
                                }

                                if (p_cond.binary_pattern.has_value())
                                {
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
                                    
                                    // 올바른 payload_len 값으로 이 호출은 이제 안전합니다.
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
                        bool MatchMessage(pcpp::SSLHandshakeMessage* msg) {
                            // 핸드셰이크 타입 검사
                            if (handshake_type.has_value()) {
                                std::string msgTypeStr = handshakeTypeToString(msg->getHandshakeType());
                                if (!iequals(handshake_type.value(), msgTypeStr)) {
                                    return false;
                                }
                            }

                            // Client Hello 메시지 처리
                            if (pcpp::SSLClientHelloMessage* clientHello = 
                                dynamic_cast<pcpp::SSLClientHelloMessage*>(msg)) {
                                
                                // 버전 검사
                                if (version.has_value()) {
                                    pcpp::SSLVersion versionObj = clientHello->getHandshakeVersion();
                                    if (!iequals(versionObj.toString(), version.value())) 
                                        return false;
                                }

                                // SNI 검사 (추가된 부분)
                                if (sni.has_value()) {
                                    pcpp::SSLServerNameIndicationExtension* sniExt = 
                                        clientHello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>();
                                    
                                    if (!sniExt) {
                                        // SNI 확장이 없으면 매칭 실패
                                        return false;
                                    }
                                    
                                    std::string pkt_sni = sniExt->getHostName();
                                    if (pkt_sni.empty() || !iequals(pkt_sni, sni.value())) {
                                        return false;
                                    }
                                }

                                // Cipher Suites 검사
                                if (cipher_suites.has_value()) {
                                    for (const auto& rule_suite_name : cipher_suites.value()) {
                                        bool found = false;
                                        for (size_t j = 0; j < clientHello->getCipherSuiteCount(); ++j) {
                                            pcpp::SSLCipherSuite* pkt_suite = clientHello->getCipherSuite(j);
                                            if (pkt_suite) {
                                                std::string suiteName = pkt_suite->asString();
                                                if (iequals(suiteName, rule_suite_name)) {
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

                            // Server Hello 메시지 처리 (SNI는 일반적으로 Client Hello에만 있음)
                            if (pcpp::SSLServerHelloMessage* serverHello = 
                                dynamic_cast<pcpp::SSLServerHelloMessage*>(msg)) {
                                
                                // 버전 검사
                                if (version.has_value()) {
                                    pcpp::SSLVersion versionObj = serverHello->getHandshakeVersion();
                                    if (!iequals(versionObj.toString(), version.value())) 
                                        return false;
                                }

                                // Cipher Suite 검사
                                if (cipher_suites.has_value()) {
                                    pcpp::SSLCipherSuite* chosenSuite = serverHello->getCipherSuite();
                                    if (!chosenSuite) return false;
                                    
                                    std::string chosenSuiteName = chosenSuite->asString();
                                    bool found = false;
                                    for (const auto& rule_suite_name : cipher_suites.value()) {
                                        if (iequals(chosenSuiteName, rule_suite_name)) {
                                            found = true;
                                            break;
                                        }
                                    }
                                    if (!found) return false;
                                }

                                // Server Hello에서 SNI를 요구하면 매칭 실패
                                if (sni.has_value()) {
                                    return false;
                                }
                                
                                return true;
                            }

                            // 다른 핸드셰이크 타입 (handshake_type만 지정된 경우)
                            if (handshake_type.has_value() && 
                                !sni.has_value() && 
                                !version.has_value() && 
                                !cipher_suites.has_value()) {
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



                    /* SSH (Supports Identification and Key Exchange Init messages)
                        - Direction is inferred from TCP ports.
                        - Supports detailed field matching for KEX messages.
                        Example 1 (Detect specific client version):
                        "ssh": {
                            "type": "identification",
                            "client_version": "SSH-2.0-OpenSSH_8.2p1"
                        }
                        Example 2 (Detect weak cipher in KEX from client):
                        "ssh": {
                            "type": "kex_init",
                            "direction": "client_to_server",
                            "encryption_algorithms_c2s_contains": "arcfour"
                        }
                        Example 3 (Detect specific KEX algorithm):
                        "ssh": {
                            "type": "kex_init",
                            "kex_algorithms_contains": "diffie-hellman-group1-sha1"
                        }
                    */
                    class ConditionSSHObject : public ConditionObjectBase
                    {
                    public:
                        explicit ConditionSSHObject(const json& sshCond)
                        {
                            std::cout << "SSH RULE DETECTED" << std::endl;
                            for (auto& [k, v] : sshCond.items())
                            {
                                if (k == "type") message_type = v.get<std::string>();
                                else if (k == "direction")
                                {
                                    std::string dir_str = v.get<std::string>();
                                    if (dir_str == "client_to_server") direction = RuleDirection::C2S;
                                    else if (dir_str == "server_to_client") direction = RuleDirection::S2C;
                                }
                                // Identification Message Fields
                                else if (k == "client_version") client_version = v.get<std::string>();
                                else if (k == "server_version") server_version = v.get<std::string>();
                                else if (k == "version_contains") version_contains = v.get<std::string>();
                                // Key Exchange Init Message Fields
                                else if (k == "kex_algorithms_contains") kex_algorithms_contains = v.get<std::string>();
                                else if (k == "server_host_key_algorithms_contains") server_host_key_algorithms_contains = v.get<std::string>();
                                else if (k == "encryption_algorithms_c2s_contains") encryption_algorithms_c2s_contains = v.get<std::string>();
                                else if (k == "encryption_algorithms_s2c_contains") encryption_algorithms_s2c_contains = v.get<std::string>();
                                else if (k == "mac_algorithms_c2s_contains") mac_algorithms_c2s_contains = v.get<std::string>();
                                else if (k == "mac_algorithms_s2c_contains") mac_algorithms_s2c_contains = v.get<std::string>();
                                else
                                    std::cerr << "[WARN] Unknown SSH condition field: " << k << std::endl;
                            }
                        }

                        bool Match(const pcpp::Packet& pkt) override
                        {
                            pcpp::SSHLayer* ssh = pkt.getLayerOfType<pcpp::SSHLayer>();
                            if (!ssh) return false;
                            // 1. Match Identification Message
                            if (auto id = dynamic_cast<pcpp::SSHIdentificationMessage*>(ssh))
                            {
                                // 규칙이 "identification" 타입을 명시했거나, 타입 명시가 없을 때만 진행
                                if (message_type.has_value() && message_type.value() != "identification")
                                    return false;
                                return MatchIdentification(id, pkt);
                            }
                            // 2. Match Key Exchange Init Message
                            else if (auto kex = dynamic_cast<pcpp::SSHKeyExchangeInitMessage*>(ssh))
                            {
                                // 규칙이 "kex_init" 타입을 명시했거나, 타입 명시가 없을 때만 진행
                                if (message_type.has_value() && message_type.value() != "kex_init")
                                    return false;
                                return MatchKexInit(kex, pkt);
                            }
                            // 다른 SSH 메시지 타입(Handshake, Encrypted)은 현재 규칙으로 지원하지 않음
                            return false;
                        }

                    private:
                        // Helper for checking if a substring exists in a comma-separated list
                        static bool list_contains(const std::string& list, const std::string& value)
                        {
                            if (list.empty() || value.empty()) return false;
                            
                            // To avoid partial matches (e.g., "sha1" in "sha128"), we check with commas
                            // This is a simplified check. For robustness, one might split the string.
                            return list.find(value) != std::string::npos;
                        }

                        bool MatchIdentification(pcpp::SSHIdentificationMessage* id, const pcpp::Packet& pkt)
                        {
                            // Identification 메시지에 대한 규칙 필드가 하나라도 있는지 확인
                            if (!client_version && !server_version && !version_contains && !direction)
                                return false;

                            pcpp::TcpLayer* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
                            if (!tcp) return false;

                            enum class PacketDirection { UNKNOWN, C2S, S2C };
                            PacketDirection packetDir = PacketDirection::UNKNOWN;
                            if (ntohs(tcp->getTcpHeader()->portDst) == 22) packetDir = PacketDirection::C2S;
                            else if (ntohs(tcp->getTcpHeader()->portSrc) == 22) packetDir = PacketDirection::S2C;

                            if (direction.has_value())
                            {
                                if (direction.value() == RuleDirection::C2S && packetDir != PacketDirection::C2S) return false;
                                if (direction.value() == RuleDirection::S2C && packetDir != PacketDirection::S2C) return false;
                            }

                            std::string pkt_version_string = id->getIdentificationMessage();
                            std::cout << "SSH : pkt_version_string : " << pkt_version_string << std::endl;
                            
                            if (client_version.has_value() && (packetDir != PacketDirection::C2S || pkt_version_string != client_version.value())) return false;
                            if (server_version.has_value() && (packetDir != PacketDirection::S2C || pkt_version_string != server_version.value())) return false;
                            if (version_contains.has_value() && pkt_version_string.find(version_contains.value()) == std::string::npos) return false;

                            return true;
                        }

                        bool MatchKexInit(pcpp::SSHKeyExchangeInitMessage* kex, const pcpp::Packet& pkt)
                        {
                            // KEX 메시지에 대한 규칙 필드가 하나라도 있는지 확인
                            if (!kex_algorithms_contains && !server_host_key_algorithms_contains &&
                                !encryption_algorithms_c2s_contains && !encryption_algorithms_s2c_contains &&
                                !mac_algorithms_c2s_contains && !mac_algorithms_s2c_contains && !direction)
                                return false;

                            pcpp::TcpLayer* tcp = pkt.getLayerOfType<pcpp::TcpLayer>();
                            if (!tcp) return false;

                            enum class PacketDirection { UNKNOWN, C2S, S2C };
                            PacketDirection packetDir = PacketDirection::UNKNOWN;
                            if (ntohs(tcp->getTcpHeader()->portDst) == 22) packetDir = PacketDirection::C2S;
                            else if (ntohs(tcp->getTcpHeader()->portSrc) == 22) packetDir = PacketDirection::S2C;

                            if (direction.has_value())
                            {
                                if (direction.value() == RuleDirection::C2S && packetDir != PacketDirection::C2S) return false;
                                if (direction.value() == RuleDirection::S2C && packetDir != PacketDirection::S2C) return false;
                            }

                            if (kex_algorithms_contains.has_value() && !list_contains(kex->getKeyExchangeAlgorithms(), kex_algorithms_contains.value())) return false;
                            if (server_host_key_algorithms_contains.has_value() && !list_contains(kex->getServerHostKeyAlgorithms(), server_host_key_algorithms_contains.value())) return false;
                            if (encryption_algorithms_c2s_contains.has_value() && !list_contains(kex->getEncryptionAlgorithmsClientToServer(), encryption_algorithms_c2s_contains.value())) return false;
                            if (encryption_algorithms_s2c_contains.has_value() && !list_contains(kex->getEncryptionAlgorithmsServerToClient(), encryption_algorithms_s2c_contains.value())) return false;
                            if (mac_algorithms_c2s_contains.has_value() && !list_contains(kex->getMacAlgorithmsClientToServer(), mac_algorithms_c2s_contains.value())) return false;
                            if (mac_algorithms_s2c_contains.has_value() && !list_contains(kex->getMacAlgorithmsServerToClient(), mac_algorithms_s2c_contains.value())) return false;

                            return true;
                        }

                        enum class RuleDirection { C2S, S2C };
                        
                        // Common fields
                        std::optional<std::string> message_type;
                        std::optional<RuleDirection> direction;
                        
                        // Identification Message fields
                        std::optional<std::string> client_version;
                        std::optional<std::string> server_version;
                        std::optional<std::string> version_contains;

                        // Key Exchange Init Message fields
                        std::optional<std::string> kex_algorithms_contains;
                        std::optional<std::string> server_host_key_algorithms_contains;
                        std::optional<std::string> encryption_algorithms_c2s_contains;
                        std::optional<std::string> encryption_algorithms_s2c_contains;
                        std::optional<std::string> mac_algorithms_c2s_contains;
                        std::optional<std::string> mac_algorithms_s2c_contains;
                    };



                    /*
                        VLAN
                        "vlan": { "id": 100, "priority": 5 }
                    */
                    class ConditionVLANObject : public ConditionObjectBase {
                    public:
                        explicit ConditionVLANObject(const json& cond) {
                            if (cond.contains("id")) id = cond["id"].get<uint16_t>();
                            if (cond.contains("priority")) priority = cond["priority"].get<uint8_t>();
                            // DEI is the modern name for CFI
                            if (cond.contains("dei")) dei = cond["dei"].get<uint8_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::VlanLayer* vlan = pkt.getLayerOfType<pcpp::VlanLayer>();
                            if (!vlan) return false;
                            if (id.has_value() && vlan->getVlanID() != id.value()) return false;
                            if (priority.has_value() && vlan->getPriority() != priority.value()) return false;
                            // Use getCFI() to check the DEI bit
                            if (dei.has_value() && vlan->getCFI() != dei.value()) return false;
                            return true;
                        }
                    private:
                        std::optional<uint16_t> id;
                        std::optional<uint8_t> priority, dei;
                    };

                    /*
                        Linux Cooked Capture (SLL)
                        "sll": { "packet_type": 0 } // 0: unicast to us
                    */
                    class ConditionSLLObject : public ConditionObjectBase {
                    public:
                        explicit ConditionSLLObject(const json& cond) {
                            if (cond.contains("packet_type")) packet_type = cond["packet_type"].get<uint16_t>();
                            if (cond.contains("addr_type")) addr_type = cond["addr_type"].get<uint16_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::SllLayer* sll = pkt.getLayerOfType<pcpp::SllLayer>();
                            if (!sll) return false;
                            if (packet_type.has_value() && ntohs(sll->getSllHeader()->packet_type) != packet_type.value()) return false;
                            if (addr_type.has_value() && ntohs(sll->getSllHeader()->ARPHRD_type) != addr_type.value()) return false;
                            return true;
                        }
                    private:
                        std::optional<uint16_t> packet_type, addr_type;
                    };

                    /*
                        Null/Loopback
                        "null_loopback": { "protocol_type": 2 } // 2: IP
                    */
                    class ConditionNullLoopbackObject : public ConditionObjectBase {
                    public:
                        explicit ConditionNullLoopbackObject(const json& cond) {
                            // "protocol_type" is a more generic name for "family" in the rule
                            if (cond.contains("protocol_type")) protocol_type = cond["protocol_type"].get<uint32_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::NullLoopbackLayer* null_lb = pkt.getLayerOfType<pcpp::NullLoopbackLayer>();
                            if (!null_lb) return false;
                            // Use getFamily() as per the header file
                            if (protocol_type.has_value() && null_lb->getFamily() != protocol_type.value()) return false;
                            return true;
                        }
                    private:
                        std::optional<uint32_t> protocol_type;
                    };

                    /*
                        PPPoE
                        "pppoe": { "type": "session", "session_id": 1234 }
                        "pppoe": { "type": "discovery", "code": 9 } // PADI
                    */
                    class ConditionPPPoEObject : public ConditionObjectBase {
                    public:
                        explicit ConditionPPPoEObject(const json& cond) {
                            if (cond.contains("type")) type = cond["type"].get<std::string>();
                            if (cond.contains("session_id")) session_id = cond["session_id"].get<uint16_t>();
                            if (cond.contains("code")) code = cond["code"].get<uint8_t>();
                            if (cond.contains("ppp_protocol")) ppp_protocol = cond["ppp_protocol"].get<uint16_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            // First, try to get the layer as a session layer
                            if (auto session = pkt.getLayerOfType<pcpp::PPPoESessionLayer>()) {
                                if (type.has_value() && type.value() != "session") return false;
                                // Session ID is in the base header, accessed via getPPPoEHeader()
                                if (session_id.has_value() && ntohs(session->getPPPoEHeader()->sessionId) != session_id.value()) return false;
                                if (ppp_protocol.has_value() && session->getPPPNextProtocol() != ppp_protocol.value()) return false;
                                // 'code' is not relevant for session layer in this context
                                if (code.has_value()) return false;
                                return true;
                            }
                            // If not a session layer, try to get it as a discovery layer
                            if (auto discovery = pkt.getLayerOfType<pcpp::PPPoEDiscoveryLayer>()) {
                                if (type.has_value() && type.value() != "discovery") return false;
                                if (session_id.has_value() && ntohs(discovery->getPPPoEHeader()->sessionId) != session_id.value()) return false;
                                if (code.has_value() && discovery->getPPPoEHeader()->code != code.value()) return false;
                                // 'ppp_protocol' is not relevant for discovery layer
                                if (ppp_protocol.has_value()) return false;
                                return true;
                            }
                            return false;
                        }
                    private:
                        std::optional<std::string> type;
                        std::optional<uint16_t> session_id, ppp_protocol;
                        std::optional<uint8_t> code;
                    };
                    
                    /*
                        VXLAN
                        "vxlan": { "vni": 4096 }
                    */
                    class ConditionVXLANObject : public ConditionObjectBase {
                    public:
                        explicit ConditionVXLANObject(const json& cond) {
                            if (cond.contains("vni")) vni = cond["vni"].get<uint32_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::VxlanLayer* vxlan = pkt.getLayerOfType<pcpp::VxlanLayer>();
                            if (!vxlan) return false;
                            if (vni.has_value() && vxlan->getVNI() != vni.value()) return false;
                            return true;
                        }
                    private:
                        std::optional<uint32_t> vni;
                    };

                    /*
                        MPLS
                        "mpls": { "label": 1001, "is_bottom_of_stack": true }
                    */
                    class ConditionMPLSObject : public ConditionObjectBase {
                    public:
                        explicit ConditionMPLSObject(const json& cond) {
                            if (cond.contains("label")) label = cond["label"].get<uint32_t>();
                            if (cond.contains("ttl")) ttl = cond["ttl"].get<uint8_t>();
                            if (cond.contains("tc")) tc = cond["tc"].get<uint8_t>();
                            if (cond.contains("is_bottom_of_stack")) is_bottom_of_stack = cond["is_bottom_of_stack"].get<bool>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::MplsLayer* mpls = pkt.getLayerOfType<pcpp::MplsLayer>();
                            if (!mpls) return false;
                            if (label.has_value() && mpls->getMplsLabel() != label.value()) return false;
                            if (ttl.has_value() && mpls->getTTL() != ttl.value()) return false;
                            if (tc.has_value() && mpls->getExperimentalUseValue() != tc.value()) return false;
                            if (is_bottom_of_stack.has_value() && mpls->isBottomOfStack() != is_bottom_of_stack.value()) return false;
                            return true;
                        }
                    private:
                        std::optional<uint32_t> label;
                        std::optional<uint8_t> ttl, tc;
                        std::optional<bool> is_bottom_of_stack;
                    };

                    /*
                        GRE
                        "gre": { "version": 0, "protocol_type": 2048 } // 0x0800 IP
                    */
                    class ConditionGREObject : public ConditionObjectBase {
                    public:
                        explicit ConditionGREObject(const json& cond) {
                            if (cond.contains("version")) version = cond["version"].get<uint8_t>();
                            if (cond.contains("protocol_type")) protocol_type = cond["protocol_type"].get<uint16_t>();
                            if (cond.contains("seq_number")) seq_number = cond["seq_number"].get<uint32_t>();
                            if (cond.contains("ack_number")) ack_number = cond["ack_number"].get<uint32_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::GreLayer* gre = pkt.getLayerOfType<pcpp::GreLayer>();
                            if (!gre) return false;

                            // Check version first
                            if (auto grev0 = dynamic_cast<pcpp::GREv0Layer*>(gre)) {
                                if (version.has_value() && version.value() != 0) return false;
                                if (protocol_type.has_value() && ntohs(grev0->getGreHeader()->protocol) != protocol_type.value()) return false;
                                
                                // Check sequence number for GREv0
                                if (seq_number.has_value()) {
                                    uint32_t pkt_seq;
                                    if (!grev0->getSequenceNumber(pkt_seq) || pkt_seq != seq_number.value()) return false;
                                }
                                // GREv0 doesn't have ACK number
                                if (ack_number.has_value()) return false;

                            } else if (auto grev1 = dynamic_cast<pcpp::GREv1Layer*>(gre)) {
                                if (version.has_value() && version.value() != 1) return false;
                                if (protocol_type.has_value() && ntohs(grev1->getGreHeader()->protocol) != protocol_type.value()) return false;

                                // Check sequence number for GREv1
                                if (seq_number.has_value()) {
                                    uint32_t pkt_seq;
                                    if (!grev1->getSequenceNumber(pkt_seq) || pkt_seq != seq_number.value()) return false;
                                }
                                // Check ACK number for GREv1
                                if (ack_number.has_value()) {
                                    uint32_t pkt_ack;
                                    if (!grev1->getAcknowledgmentNum(pkt_ack) || pkt_ack != ack_number.value()) return false;
                                }
                            } else {
                                // Neither GREv0 nor GREv1, something is wrong
                                return false;
                            }
                            
                            return true;
                        }
                    private:
                        std::optional<uint8_t> version;
                        std::optional<uint16_t> protocol_type;
                        std::optional<uint32_t> seq_number, ack_number;
                    };

                    /*
                        ICMPv6
                        "icmpv6": { "type": 128, "code": 0 } // Echo Request
                    */
                    class ConditionICMPV6Object : public ConditionObjectBase {
                     public:
                        explicit ConditionICMPV6Object(const json& cond) {
                            if (cond.contains("type")) type = cond["type"].get<uint8_t>();
                            if (cond.contains("code")) code = cond["code"].get<uint8_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::IcmpV6Layer* icmpv6 = pkt.getLayerOfType<pcpp::IcmpV6Layer>();
                            if (!icmpv6) return false;
                            // getMessageType() returns an enum, so cast to underlying type (int) then to uint8_t
                            if (type.has_value() && static_cast<uint8_t>(icmpv6->getMessageType()) != type.value()) return false;
                            if (code.has_value() && icmpv6->getCode() != code.value()) return false;
                            return true;
                        }
                    private:
                        std::optional<uint8_t> type, code;
                    };

                    

                    /*
                        VRRP
                        "vrrp": { "type": "advertisement", "vrid": 10 }
                    */
                    class ConditionVRRPObject : public ConditionObjectBase {
                    public:
                        explicit ConditionVRRPObject(const json& cond) {
                            if (cond.contains("version")) version = cond["version"].get<uint8_t>();
                            if (cond.contains("type")) type = cond["type"].get<std::string>();
                            if (cond.contains("vrid")) vrid = cond["vrid"].get<uint8_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::VrrpLayer* vrrp = pkt.getLayerOfType<pcpp::VrrpLayer>();
                            if (!vrrp) return false;

                            // Check version first
                            if (version.has_value() && vrrp->getVersion() != version.value()) return false;
                            
                            // Common fields
                            if (vrid.has_value() && vrrp->getVirtualRouterID() != vrid.value()) return false;
                            if (type.has_value()) {
                                // getType() returns VrrpType enum
                                if (type.value() == "advertisement" && vrrp->getType() != pcpp::VrrpLayer::VrrpType_Advertisement) return false;
                            }
                            return true;
                        }
                    private:
                        std::optional<uint8_t> version, vrid;
                        std::optional<std::string> type;
                    };

                    /*
                        WireGuard
                        "wireguard": { "message_type": "handshake_initiation" }
                    */
                    class ConditionWireGuardObject : public ConditionObjectBase {
                    public:
                        explicit ConditionWireGuardObject(const json& cond) {
                            if (cond.contains("message_type")) message_type = cond["message_type"].get<std::string>();
                            if (cond.contains("sender_index")) sender_index = cond["sender_index"].get<uint32_t>();
                            if (cond.contains("receiver_index")) receiver_index = cond["receiver_index"].get<uint32_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::WireGuardLayer* wg = pkt.getLayerOfType<pcpp::WireGuardLayer>();
                            if (!wg) return false;

                            // Match against specific message types
                            if (auto wg_init = dynamic_cast<pcpp::WireGuardHandshakeInitiationLayer*>(wg)) {
                                if (message_type.has_value() && message_type.value() != "handshake_initiation") return false;
                                if (sender_index.has_value() && wg_init->getSenderIndex() != sender_index.value()) return false;
                                if (receiver_index.has_value()) return false; // This message type only has sender_index
                            }
                            else if (auto wg_resp = dynamic_cast<pcpp::WireGuardHandshakeResponseLayer*>(wg)) {
                                if (message_type.has_value() && message_type.value() != "handshake_response") return false;
                                if (sender_index.has_value() && wg_resp->getSenderIndex() != sender_index.value()) return false;
                                if (receiver_index.has_value() && wg_resp->getReceiverIndex() != receiver_index.value()) return false;
                            }
                            else if (auto wg_cookie = dynamic_cast<pcpp::WireGuardCookieReplyLayer*>(wg)) {
                                if (message_type.has_value() && message_type.value() != "cookie_reply") return false;
                                if (sender_index.has_value()) return false;
                                if (receiver_index.has_value() && wg_cookie->getReceiverIndex() != receiver_index.value()) return false;
                            }
                            else if (auto wg_data = dynamic_cast<pcpp::WireGuardTransportDataLayer*>(wg)) {
                                if (message_type.has_value() && message_type.value() != "transport_data") return false;
                                if (sender_index.has_value()) return false;
                                if (receiver_index.has_value() && wg_data->getReceiverIndex() != receiver_index.value()) return false;
                            }
                            else {
                                // Unknown or base WireGuard type, only check generic type if rule is generic
                                if (message_type.has_value()) return false;
                            }
                            
                            return true;
                        }
                    private:
                        std::optional<std::string> message_type;
                        std::optional<uint32_t> sender_index, receiver_index;
                    };

                    /*
                        GTP (GPRS Tunneling Protocol)
                        "gtp": { "version": 1, "message_type": "echo_request" }
                    */
                    class ConditionGTPObject : public ConditionObjectBase {
                    public:
                        explicit ConditionGTPObject(const json& cond) {
                            if (cond.contains("version")) version = cond["version"].get<uint8_t>();
                            if (cond.contains("message_type")) message_type = cond["message_type"].get<std::string>();
                            if (cond.contains("teid")) teid = cond["teid"].get<uint32_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            // Check for GTPv1 first
                            if (auto gtpv1 = pkt.getLayerOfType<pcpp::GtpV1Layer>()) {
                                if (version.has_value() && version.value() != 1) return false;
                                if (teid.has_value() && ntohl(gtpv1->getHeader()->teid) != teid.value()) return false;
                                if (message_type.has_value()) {
                                    std::string msgTypeStr = gtpv1->getMessageTypeAsString();
                                    // Convert rule's snake_case to Pcap++'s PascalCase-like string
                                    std::string expected_str = message_type.value();
                                    std::replace(expected_str.begin(), expected_str.end(), '_', ' ');
                                    expected_str[0] = toupper(expected_str[0]);
                                    // This is a simplified comparison, might need a map for accuracy
                                    if (msgTypeStr.find(expected_str) == std::string::npos) return false;
                                }
                                return true;
                            }
                            // Then check for GTPv2
                            else if (auto gtpv2 = pkt.getLayerOfType<pcpp::GtpV2Layer>()) {
                                if (version.has_value() && version.value() != 2) return false;
                                auto teid_pair = gtpv2->getTeid();
                                if (teid.has_value()) {
                                    if (!teid_pair.first || teid_pair.second != teid.value()) return false;
                                }
                                if (message_type.has_value()) {
                                    std::string msgTypeStr = gtpv2->getMessageType().toString();
                                    if (msgTypeStr.find(message_type.value()) == std::string::npos) return false;
                                }
                                return true;
                            }
                            return false;
                        }
                    private:
                        std::optional<uint8_t> version;
                        std::optional<std::string> message_type;
                        std::optional<uint32_t> teid;
                    };

                    /*
                        SIP (Session Initiation Protocol)
                        "sip": { "type": "request", "method": "INVITE" }
                        "sip": { "type": "response", "status_code": 200 }
                    */
                    class ConditionSIPObject : public ConditionObjectBase {
                    public:
                        explicit ConditionSIPObject(const json& cond) {
                            if (cond.contains("type")) type = cond["type"].get<std::string>();
                            if (cond.contains("method")) method = cond["method"].get<std::string>();
                            if (cond.contains("status_code")) status_code = cond["status_code"].get<int>();
                            if (cond.contains("uri_contains")) uri_contains = cond["uri_contains"].get<std::string>();
                            if (cond.contains("header_contains")) header_contains = cond["header_contains"].get<std::string>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            if (auto req = pkt.getLayerOfType<pcpp::SipRequestLayer>()) {
                                if (type.has_value() && type.value() != "request") return false;
                                pcpp::SipRequestFirstLine* firstLine = req->getFirstLine();
                                if (!firstLine || !firstLine->isComplete()) return false;

                                if (method.has_value()) {
                                    // --- 수정된 부분 ---
                                    // getMethod()가 반환하는 enum 값을 문자열로 변환
                                    std::string methodStr = sipMethodToString(firstLine->getMethod());
                                    if (methodStr != method.value()) return false;
                                    // --- 수정 끝 ---
                                }

                                if (uri_contains.has_value() && firstLine->getUri().find(uri_contains.value()) == std::string::npos) return false;
                                
                                if (header_contains.has_value()) {
                                    // getFieldByName은 TextBasedProtocolMessage에 있는 메서드
                                    auto field = req->getFieldByName(header_contains.value());
                                    if (field == nullptr) return false;
                                }
                                return true;
                            }
                            if (auto res = pkt.getLayerOfType<pcpp::SipResponseLayer>()) {
                                if (type.has_value() && type.value() != "response") return false;
                                pcpp::SipResponseFirstLine* firstLine = res->getFirstLine();
                                if (!firstLine || !firstLine->isComplete()) return false;

                                if (status_code.has_value() && firstLine->getStatusCodeAsInt() != status_code.value()) return false;
                                
                                if (header_contains.has_value()) {
                                    auto field = res->getFieldByName(header_contains.value());
                                    if (field == nullptr) return false;
                                }
                                return true;
                            }
                            return false;
                        }
                    private:
                        // --- 추가된 Helper 함수 ---
                        static std::string sipMethodToString(pcpp::SipRequestLayer::SipMethod method) {
                            switch (method) {
                                case pcpp::SipRequestLayer::SipINVITE:    return "INVITE";
                                case pcpp::SipRequestLayer::SipACK:       return "ACK";
                                case pcpp::SipRequestLayer::SipBYE:       return "BYE";
                                case pcpp::SipRequestLayer::SipCANCEL:    return "CANCEL";
                                case pcpp::SipRequestLayer::SipREGISTER:  return "REGISTER";
                                case pcpp::SipRequestLayer::SipOPTIONS:   return "OPTIONS";
                                case pcpp::SipRequestLayer::SipSUBSCRIBE: return "SUBSCRIBE";
                                case pcpp::SipRequestLayer::SipNOTIFY:    return "NOTIFY";
                                case pcpp::SipRequestLayer::SipPUBLISH:   return "PUBLISH";
                                case pcpp::SipRequestLayer::SipINFO:      return "INFO";
                                case pcpp::SipRequestLayer::SipREFER:     return "REFER";
                                case pcpp::SipRequestLayer::SipMESSAGE:   return "MESSAGE";
                                case pcpp::SipRequestLayer::SipUPDATE:    return "UPDATE";
                                default:                                  return "Unknown";
                            }
                        }
                        // --- Helper 함수 끝 ---

                        std::optional<std::string> type, method, uri_contains, header_contains;
                        std::optional<int> status_code;
                    };
                    
                    /*
                        DHCP
                        "dhcp": { "message_type": "discover" }
                    */
                    class ConditionDHCPObject : public ConditionObjectBase {
                    public:
                        explicit ConditionDHCPObject(const json& cond) {
                            if (cond.contains("message_type")) message_type = cond["message_type"].get<std::string>();
                            if (cond.contains("op_code")) op_code = cond["op_code"].get<uint8_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::DhcpLayer* dhcp = pkt.getLayerOfType<pcpp::DhcpLayer>();
                            if (!dhcp) return false;
                            if (op_code.has_value() && dhcp->getDhcpHeader()->opCode != op_code.value()) return false;
                            if (message_type.has_value()) {
                                auto dhcpMessageType = dhcp->getMessageType();
                                if (dhcpMessageType == pcpp::DHCP_UNKNOWN_MSG_TYPE) return false;
                                if (message_type.value() == "discover" && dhcpMessageType != pcpp::DHCP_DISCOVER) return false;
                                if (message_type.value() == "offer" && dhcpMessageType != pcpp::DHCP_OFFER) return false;
                                if (message_type.value() == "request" && dhcpMessageType != pcpp::DHCP_REQUEST) return false;
                                if (message_type.value() == "ack" && dhcpMessageType != pcpp::DHCP_ACK) return false;
                                if (message_type.value() == "nak" && dhcpMessageType != pcpp::DHCP_NAK) return false;
                                if (message_type.value() == "release" && dhcpMessageType != pcpp::DHCP_RELEASE) return false;
                                if (message_type.value() == "inform" && dhcpMessageType != pcpp::DHCP_INFORM) return false;
                                if (message_type.value() == "decline" && dhcpMessageType != pcpp::DHCP_DECLINE) return false;
                            }
                            return true;
                        }
                    private:
                        std::optional<std::string> message_type;
                        std::optional<uint8_t> op_code;
                    };

                    /*
                        FTP
                        "ftp": { "type": "request", "command": "USER" }
                        "ftp": { "type": "response", "status_code": 220 }
                    */
                    class ConditionFTPObject : public ConditionObjectBase {
                    public:
                        explicit ConditionFTPObject(const json& cond) {
                            if (cond.contains("type")) type = cond["type"].get<std::string>();
                            if (cond.contains("command")) command = cond["command"].get<std::string>();
                            if (cond.contains("status_code")) status_code = cond["status_code"].get<int>();
                            if (cond.contains("message_contains")) message_contains = cond["message_contains"].get<std::string>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            if (auto req = pkt.getLayerOfType<pcpp::FtpRequestLayer>()) {
                                if (type.has_value() && type.value() != "request") return false;
                                if (command.has_value() && req->getCommandString() != command.value()) return false;
                                if (message_contains.has_value() && req->getCommandOption().find(message_contains.value()) == std::string::npos) return false;
                                return true;
                            }
                            if (auto res = pkt.getLayerOfType<pcpp::FtpResponseLayer>()) {
                                if (type.has_value() && type.value() != "response") return false;
                                // getStatusCode() returns enum, need to cast to int
                                if (status_code.has_value() && static_cast<int>(res->getStatusCode()) != status_code.value()) return false;
                                // FtpResponseLayer doesn't have a direct getResponseMessage() method.
                                // getStatusOption() gets the message part.
                                if (message_contains.has_value() && res->getStatusOption().find(message_contains.value()) == std::string::npos) return false;
                                return true;
                            }
                            return false;
                        }
                    private:
                        std::optional<std::string> type, command, message_contains;
                        std::optional<int> status_code;
                    };

                    /*
                        Telnet
                        "telnet": { "data_contains": "login:" }
                    */
                    class ConditionTelnetObject : public ConditionObjectBase {
                    public:
                        explicit ConditionTelnetObject(const json& cond) {
                            if (cond.contains("command")) command_str = cond["command"].get<std::string>();
                            if (cond.contains("data_contains")) data_contains = cond["data_contains"].get<std::string>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::TelnetLayer* telnet = pkt.getLayerOfType<pcpp::TelnetLayer>();
                            if (!telnet) return false;
                            
                            if (command_str.has_value()) {
                                bool command_found = false;
                                pcpp::TelnetLayer::TelnetCommand cmd = telnet->getFirstCommand();
                                while (cmd != pcpp::TelnetLayer::TelnetCommand::TelnetCommandEndOfPacket) {
                                    if (pcpp::TelnetLayer::getTelnetCommandAsString(cmd) == command_str.value()) {
                                        command_found = true;
                                        break;
                                    }
                                    cmd = telnet->getNextCommand();
                                }
                                if (!command_found) return false;
                            }

                            if (data_contains.has_value()) {
                                std::string data = telnet->getDataAsString(false); // keep escape characters
                                if (data.find(data_contains.value()) == std::string::npos) return false;
                            }
                            return true;
                        }
                    private:
                        std::optional<std::string> command_str;
                        std::optional<std::string> data_contains;
                    };

                    /*
                        NTP
                        "ntp": { "mode": "client", "stratum": 3 }
                    */
                    class ConditionNTPObject : public ConditionObjectBase {
                    public:
                        explicit ConditionNTPObject(const json& cond) {
                            if (cond.contains("mode")) mode = cond["mode"].get<std::string>();
                            if (cond.contains("stratum")) stratum = cond["stratum"].get<uint8_t>();
                            if (cond.contains("leap_indicator")) leap_indicator = cond["leap_indicator"].get<std::string>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::NtpLayer* ntp = pkt.getLayerOfType<pcpp::NtpLayer>();
                            if (!ntp) return false;
                            if (stratum.has_value() && ntp->getStratum() != stratum.value()) return false;
                            if (mode.has_value()) {
                                pcpp::NtpLayer::Mode ntpMode = ntp->getMode();
                                if (mode.value() == "client" && ntpMode != pcpp::NtpLayer::Client) return false;
                                if (mode.value() == "server" && ntpMode != pcpp::NtpLayer::Server) return false;
                                if (mode.value() == "symmetric_active" && ntpMode != pcpp::NtpLayer::SymActive) return false;
                                // ... add other modes as needed
                            }
                            if (leap_indicator.has_value()) {
                                pcpp::NtpLayer::LeapIndicator li = ntp->getLeapIndicator();
                                if (leap_indicator.value() == "no_warning" && li != pcpp::NtpLayer::NoWarning) return false;
                                if (leap_indicator.value() == "sixty_one_seconds" && li != pcpp::NtpLayer::Last61Secs) return false;
                                if (leap_indicator.value() == "fifty_nine_seconds" && li != pcpp::NtpLayer::Last59Secs) return false;
                            }
                            return true;
                        }
                    private:
                        std::optional<std::string> mode, leap_indicator;
                        std::optional<uint8_t> stratum;
                    };

                    /*
                        SMTP
                        "smtp": { "command": "HELO" }
                    */
                    class ConditionSMTPObject : public ConditionObjectBase {
                    public:
                        explicit ConditionSMTPObject(const json& cond) {
                            if (cond.contains("command")) command = cond["command"].get<std::string>();
                            if (cond.contains("data_contains")) data_contains = cond["data_contains"].get<std::string>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::SmtpLayer* smtp = pkt.getLayerOfType<pcpp::SmtpLayer>();
                            if (!smtp) return false;
                            // Pcap++ SMTP support is basic, primarily for payload.
                            // We inspect the payload directly for commands/responses.
                            std::string payload(reinterpret_cast<const char*>(smtp->getLayerPayload()), smtp->getLayerPayloadSize());
                            if (command.has_value() && payload.rfind(command.value(), 0) != 0) return false; // Starts with command
                            if (data_contains.has_value() && payload.find(data_contains.value()) == std::string::npos) return false;
                            return true;
                        }
                    private:
                        std::optional<std::string> command, data_contains;
                    };
                    
                    /*
                        RADIUS
                        "radius": { "code": "access_request", "id": 123 }
                    */
                    class ConditionRADIUSObject : public ConditionObjectBase {
                    public:
                        explicit ConditionRADIUSObject(const json& cond) {
                            if (cond.contains("code")) code = cond["code"].get<std::string>();
                            if (cond.contains("id")) id = cond["id"].get<uint8_t>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::RadiusLayer* radius = pkt.getLayerOfType<pcpp::RadiusLayer>();
                            if (!radius) return false;
                            if (id.has_value() && radius->getRadiusHeader()->id != id.value()) return false;
                            if (code.has_value()) {
                                uint8_t pktCode = radius->getRadiusHeader()->code;
                                if (code.value() == "access_request" && pktCode != 1) return false;
                                if (code.value() == "access_accept" && pktCode != 2) return false;
                                if (code.value() == "access_reject" && pktCode != 3) return false;
                            }
                            return true;
                        }
                    private:
                        std::optional<std::string> code;
                        std::optional<uint8_t> id;
                    };
                    
                    /*
                        LDAP
                        "ldap": { "op_code": "search_request", "message_id": 1 }
                    */
                    class ConditionLDAPObject : public ConditionObjectBase {
                    public:
                        explicit ConditionLDAPObject(const json& cond) {
                            if (cond.contains("op_code")) op_code = cond["op_code"].get<std::string>();
                            if (cond.contains("message_id")) message_id = cond["message_id"].get<int>();
                        }
                        bool Match(const pcpp::Packet& pkt) override {
                            pcpp::LdapLayer* ldap = pkt.getLayerOfType<pcpp::LdapLayer>();
                            if (!ldap) return false;

                            uint16_t pkt_msg_id;
                            if (!ldap->tryGet(&pcpp::LdapLayer::getMessageID, pkt_msg_id)) return false;
                            if (message_id.has_value() && pkt_msg_id != message_id.value()) return false;
                            
                            if (op_code.has_value()) {
                                pcpp::LdapOperationType opType;
                                if (!ldap->tryGet(&pcpp::LdapLayer::getLdapOperationType, opType)) return false;

                                std::string opCodeStr = opType.toString();
                                // Rule uses snake_case, Pcap++ uses PascalCase, need conversion/mapping
                                // This is a simplified check
                                std::string expected_str = op_code.value();
                                std::replace(expected_str.begin(), expected_str.end(), '_', ' ');
                                if (opCodeStr.find(expected_str) == std::string::npos) return false;
                            }
                            return true;
                        }
                    private:
                        std::optional<std::string> op_code;
                        std::optional<int> message_id;
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
                                else if (protocol == ProtocolKey::SSH)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionSSHObject>(condObj));

                                else if (protocol == ProtocolKey::VLAN)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionVLANObject>(condObj));
                                else if (protocol == ProtocolKey::SLL)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionSLLObject>(condObj));
                                else if (protocol == ProtocolKey::NULL_LOOPBACK)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionNullLoopbackObject>(condObj));
                                else if (protocol == ProtocolKey::PPPOE)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionPPPoEObject>(condObj));
                                else if (protocol == ProtocolKey::VXLAN)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionVXLANObject>(condObj));
                                else if (protocol == ProtocolKey::MPLS)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionMPLSObject>(condObj));
                                else if (protocol == ProtocolKey::GRE)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionGREObject>(condObj));
                                else if (protocol == ProtocolKey::ICMPV6)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionICMPV6Object>(condObj));
                                //else if (protocol == ProtocolKey::NDP)
                                    //conditions.push_back(std::make_unique<ConditionLogic::ConditionNDPObject>(condObj));
                                else if (protocol == ProtocolKey::VRRP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionVRRPObject>(condObj));
                                else if (protocol == ProtocolKey::WIREGUARD)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionWireGuardObject>(condObj));
                                //else if (protocol == ProtocolKey::IPSEC)
                                    //conditions.push_back(std::make_unique<ConditionLogic::ConditionIPSecObject>(condObj));
                                else if (protocol == ProtocolKey::GTP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionGTPObject>(condObj));
                                else if (protocol == ProtocolKey::SIP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionSIPObject>(condObj));
                                else if (protocol == ProtocolKey::DHCP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionDHCPObject>(condObj));
                                else if (protocol == ProtocolKey::FTP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionFTPObject>(condObj));
                                else if (protocol == ProtocolKey::TELNET)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionTelnetObject>(condObj));
                                else if (protocol == ProtocolKey::NTP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionNTPObject>(condObj));
                                else if (protocol == ProtocolKey::SMTP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionSMTPObject>(condObj));
                                else if (protocol == ProtocolKey::RADIUS)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionRADIUSObject>(condObj));
                                else if (protocol == ProtocolKey::LDAP)
                                    conditions.push_back(std::make_unique<ConditionLogic::ConditionLDAPObject>(condObj));

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