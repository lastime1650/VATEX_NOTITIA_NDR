#ifndef PACKET_TO_JSON_HPP
#define PACKET_TO_JSON_HPP

#include <string>
#include <algorithm>
#include <vector>

#include "../../util/util.hpp"

// PcapPlusPlus 헤더
#include <pcapplusplus/Packet.h>
#include <pcapplusplus/EthLayer.h>
#include <pcapplusplus/ArpLayer.h>
#include <pcapplusplus/IPv4Layer.h>
#include <pcapplusplus/IPv6Layer.h>
#include <pcapplusplus/TcpLayer.h>
#include <pcapplusplus/UdpLayer.h>
#include <pcapplusplus/IcmpLayer.h>
#include <pcapplusplus/DnsLayer.h>
#include <pcapplusplus/HttpLayer.h>
#include <pcapplusplus/SSLLayer.h>
#include <pcapplusplus/SSHLayer.h>
#include <pcapplusplus/PayloadLayer.h>

namespace PacketParser
{
    // --- 헬퍼 함수들 ---

    namespace helpers
    {

        

        std::string dnsTypeToString(pcpp::DnsType type) {
            switch (type) {
                case pcpp::DNS_TYPE_A: return "A";
                case pcpp::DNS_TYPE_AAAA: return "AAAA";
                case pcpp::DNS_TYPE_CNAME: return "CNAME";
                case pcpp::DNS_TYPE_PTR: return "PTR";
                case pcpp::DNS_TYPE_MX: return "MX";
                case pcpp::DNS_TYPE_TXT: return "TXT";
                case pcpp::DNS_TYPE_SRV: return "SRV";
                case pcpp::DNS_TYPE_NS: return "NS";
                case pcpp::DNS_TYPE_SOA: return "SOA";
                default: return "Type" + std::to_string(static_cast<int>(type));
            }
        }

        std::string httpMethodToString(pcpp::HttpRequestLayer::HttpMethod method) {
            switch(method) {
                case pcpp::HttpRequestLayer::HttpGET: return "GET";
                case pcpp::HttpRequestLayer::HttpPOST: return "POST";
                case pcpp::HttpRequestLayer::HttpHEAD: return "HEAD";
                case pcpp::HttpRequestLayer::HttpPUT: return "PUT";
                case pcpp::HttpRequestLayer::HttpDELETE: return "DELETE";
                case pcpp::HttpRequestLayer::HttpTRACE: return "TRACE";
                case pcpp::HttpRequestLayer::HttpOPTIONS: return "OPTIONS";
                case pcpp::HttpRequestLayer::HttpCONNECT: return "CONNECT";
                case pcpp::HttpRequestLayer::HttpPATCH: return "PATCH";
                default: return "Unknown";
            }
        }

        std::string bytesToHexString(const uint8_t* data, size_t len) {
            if (data == nullptr || len == 0) {
                return "";
            }
            std::string hex_str;
            hex_str.reserve(len * 2);
            for (size_t i = 0; i < len; ++i) {
                char buf[3];
                snprintf(buf, sizeof(buf), "%02x", data[i]);
                hex_str.append(buf);
            }
            return hex_str;
        }

    } // namespace helpers

    // --- 각 레이어별 파싱 함수 ---

    json parseSSHLayer(const pcpp::SSHLayer* sshLayer)  {
        json j;
        if (!sshLayer) return j;


        // 상속 관계 때문에 가장 구체적인 타입부터 확인해야 합니다.
        // SSHKeyExchangeInitMessage -> SSHHandshakeMessage -> SSHLayer
        if (auto kexInit = dynamic_cast<pcpp::SSHKeyExchangeInitMessage*>(const_cast<pcpp::SSHLayer*>(sshLayer)))  {
            j["type"] = "Key Exchange Init";
            j["message_type_str"] = kexInit->getMessageTypeStr();
            j["cookie"] = kexInit->getCookieAsHexStream();
            j["kex_algorithms"] = kexInit->getKeyExchangeAlgorithms();
            j["server_host_key_algorithms"] = kexInit->getServerHostKeyAlgorithms();
            j["encryption_algorithms_c2s"] = kexInit->getEncryptionAlgorithmsClientToServer();
            j["encryption_algorithms_s2c"] = kexInit->getEncryptionAlgorithmsServerToClient();
            j["mac_algorithms_c2s"] = kexInit->getMacAlgorithmsClientToServer();
            j["mac_algorithms_s2c"] = kexInit->getMacAlgorithmsServerToClient();
            j["compression_algorithms_c2s"] = kexInit->getCompressionAlgorithmsClientToServer();
            j["compression_algorithms_s2c"] = kexInit->getCompressionAlgorithmsServerToClient();
            j["languages_c2s"] = kexInit->getLanguagesClientToServer();
            j["languages_s2c"] = kexInit->getLanguagesServerToClient();
            j["first_kex_packet_follows"] = kexInit->isFirstKexPacketFollows();
            j["padding_length"] = kexInit->getPaddingLength();
        }
        else if (auto handshake = dynamic_cast<const pcpp::SSHHandshakeMessage*>(sshLayer)) {
            j["type"] = "Handshake";
            j["message_type_str"] = handshake->getMessageTypeStr();
            j["message_type_code"] = handshake->getMessageType();
            j["content_length"] = handshake->getSSHHandshakeMessageLength();
            j["padding_length"] = handshake->getPaddingLength();
        }
        
        else if (auto id = dynamic_cast<pcpp::SSHIdentificationMessage*>(const_cast<pcpp::SSHLayer*>(sshLayer))) {
            j["type"] = "Identification";
            j["message"] = id->getIdentificationMessage();
        }
        else if (auto encrypted = dynamic_cast<const pcpp::SSHEncryptedMessage*>(sshLayer)) {
            j["type"] = "Encrypted Message";
            j["length"] = encrypted->getHeaderLen();
        }
        else {
            j["type"] = "Unknown SSH Message";
            j["length"] = sshLayer->getHeaderLen();
        }
        std::cout << "SSH:" << j.dump() << std::endl;
        return j;
    }

    json parseEthLayer(const pcpp::EthLayer* ethLayer) {
        json j;
        if (!ethLayer) return j;
        j["src_mac"] = ethLayer->getSourceMac().toString();
        j["dst_mac"] = ethLayer->getDestMac().toString();
        j["ether_type"] = ntohs(ethLayer->getEthHeader()->etherType);
        return j;
    }

    json parseArpLayer(const pcpp::ArpLayer* arpLayer) {
        json j;
        if (!arpLayer) return j;
        j["opcode"] = ntohs(arpLayer->getArpHeader()->opcode);
        j["sender_mac"] = arpLayer->getSenderMacAddress().toString();
        j["sender_ip"] = arpLayer->getSenderIpAddr().toString();
        j["target_mac"] = arpLayer->getTargetMacAddress().toString();
        j["target_ip"] = arpLayer->getTargetIpAddr().toString();
        return j;
    }

    json parseIPv4Layer(const pcpp::IPv4Layer* ipLayer) {
        json j;
        if (!ipLayer)
            return j;

        const pcpp::iphdr* hdr = ipLayer->getIPv4Header();

        j["version"]        = static_cast<int>(hdr->ipVersion);
        j["src_ip"]         = ipLayer->getSrcIPAddress().toString();
        j["dst_ip"]         = ipLayer->getDstIPAddress().toString();
        j["protocol"]       = static_cast<int>(hdr->protocol);
        j["ttl"]            = static_cast<int>(hdr->timeToLive);
        j["total_length"]   = ntohs(hdr->totalLength);
        j["header_length"]  = ipLayer->getHeaderLen();
        j["is_fragment"]    = ipLayer->isFragment();
        j["fragment_offset"]= ipLayer->getFragmentOffset();

        return j;
    }

    
    json parseIPv6Layer(const pcpp::IPv6Layer* ipv6Layer) {
        json j;
        if (!ipv6Layer) return j;
        j["version"] = 6;
        j["src_ip"] = ipv6Layer->getSrcIPv6Address().toString();
        j["dst_ip"] = ipv6Layer->getDstIPv6Address().toString();
        j["next_header"] = static_cast<int>(ipv6Layer->getIPv6Header()->nextHeader);
        j["hop_limit"] = static_cast<int>(ipv6Layer->getIPv6Header()->hopLimit);
        return j;
    }

    json parseTcpLayer(const pcpp::TcpLayer* tcpLayer) {
        json j;
        if (!tcpLayer) return j;
        const pcpp::tcphdr* hdr = tcpLayer->getTcpHeader();
        j["src_port"] = ntohs(hdr->portSrc);
        j["dst_port"] = ntohs(hdr->portDst);
        j["seq"] = ntohl(hdr->sequenceNumber);
        j["ack"] = ntohl(hdr->ackNumber);
        j["window_size"] = ntohs(hdr->windowSize);
        j["payload_size"] = tcpLayer->getLayerPayloadSize();

        json flags = json::array();
        if (hdr->synFlag) flags.push_back("SYN");
        if (hdr->ackFlag) flags.push_back("ACK");
        if (hdr->finFlag) flags.push_back("FIN");
        if (hdr->rstFlag) flags.push_back("RST");
        if (hdr->pshFlag) flags.push_back("PSH");
        if (hdr->urgFlag) flags.push_back("URG");
        if (hdr->cwrFlag) flags.push_back("CWR");
        if (hdr->eceFlag) flags.push_back("ECE");
        j["flags"] = flags;
        
        return j;
    }

    json parseUdpLayer(const pcpp::UdpLayer* udpLayer) {
        json j;
        if (!udpLayer) return j;
        j["src_port"] = ntohs(udpLayer->getUdpHeader()->portSrc);
        j["dst_port"] = ntohs(udpLayer->getUdpHeader()->portDst);
        j["length"] = ntohs(udpLayer->getUdpHeader()->length);
        j["payload_size"] = udpLayer->getLayerPayloadSize();
        return j;
    }

    json parseIcmpLayer(const pcpp::IcmpLayer* icmpLayer) {
        json j;
        if (!icmpLayer) return j;
        j["type"] = static_cast<int>(icmpLayer->getIcmpHeader()->type);
        j["code"] = static_cast<int>(icmpLayer->getIcmpHeader()->code);
        return j;
    }

    json parseDnsLayer(const pcpp::DnsLayer* dnsLayer) {
        json j;
        if (!dnsLayer) return j;
        
        j["transaction_id"] = ntohs(dnsLayer->getDnsHeader()->transactionID);
        j["is_response"] = (dnsLayer->getDnsHeader()->queryOrResponse != 0);
        
        json queries = json::array();
        for ( pcpp::DnsQuery* q = dnsLayer->getFirstQuery(); q != nullptr; q = dnsLayer->getNextQuery(q)) {
            json query;
            query["name"] = q->getName();
            query["type"] = helpers::dnsTypeToString(q->getDnsType());
            queries.push_back(query);
        }
        if (!queries.empty()) j["queries"] = queries;
        
        json answers = json::array();
        for ( pcpp::DnsResource* a = dnsLayer->getFirstAnswer(); a != nullptr; a = dnsLayer->getNextAnswer(a)) {
            json answer;
            answer["name"] = a->getName();
            answer["type"] = helpers::dnsTypeToString(a->getDnsType());
            answer["ttl"] = a->getTTL();
            if (a->getData()) {
                answer["data"] = a->getData()->toString();
            }
            answers.push_back(answer);
        }
        if (!answers.empty()) j["answers"] = answers;
        
        return j;
    }

    json parseHttpLayer(const pcpp::Layer* httpLayer) {
        json j;
        if (!httpLayer) return j;

        if (auto req = dynamic_cast<const pcpp::HttpRequestLayer*>(httpLayer)) {
            j["type"] = "request";
            j["method"] = helpers::httpMethodToString(req->getFirstLine()->getMethod());
            j["uri"] = req->getFirstLine()->getUri();
            json headers;
            for (pcpp::HeaderField* h = req->getFirstField(); h != nullptr; h = req->getNextField(h)) {
                headers[h->getFieldName()] = h->getFieldValue();
            }
            j["headers"] = headers;
            j["body_size"] = req->getLayerPayloadSize();
        } else if (auto res = dynamic_cast<const pcpp::HttpResponseLayer*>(httpLayer)) {
            j["type"] = "response";
            j["status_code"] = res->getFirstLine()->getStatusCodeAsInt();
            j["reason_phrase"] = res->getFirstLine()->getStatusCodeString();
            json headers;
            for (pcpp::HeaderField* h = res->getFirstField(); h != nullptr; h = res->getNextField(h)) {
                headers[h->getFieldName()] = h->getFieldValue();
            }
            j["headers"] = headers;
            j["body_size"] = res->getLayerPayloadSize();
        }
        return j;
    }
    
    json parseSSLLayer(const pcpp::SSLLayer* sslLayer) {
    json j;
    if (!sslLayer) return j;

    if (auto handshakeLayer = dynamic_cast<const pcpp::SSLHandshakeLayer*>(sslLayer)) {
        j["type"] = "Handshake";
        json messages = json::array();

        for (size_t i = 0; i < handshakeLayer->getHandshakeMessagesCount(); ++i) {
            auto* msg = handshakeLayer->getHandshakeMessageAt(i);
            if (!msg) continue;

            json msg_json;
            msg_json["handshake_type"] = msg->toString();

            // ClientHello 처리
            if (auto clientHello = dynamic_cast<pcpp::SSLClientHelloMessage*>(msg)) {
                // SNI
                if (auto sniExt = clientHello->getExtensionOfType<pcpp::SSLServerNameIndicationExtension>())
                    msg_json["sni"] = sniExt->getHostName();
                else
                    msg_json["sni"] = nullptr;

                // TLS Version
                msg_json["version"] = clientHello->getHandshakeVersion().toString();

                // Cipher Suites
                json suites = json::array();
                for (size_t j = 0; j < clientHello->getCipherSuiteCount(); ++j) {
                    if (auto cs = clientHello->getCipherSuite(j))
                        suites.push_back(cs->asString());
                }
                msg_json["cipher_suites"] = suites;
            }

            // ServerHello 처리
            if (auto serverHello = dynamic_cast<pcpp::SSLServerHelloMessage*>(msg)) {
                msg_json["version"] = serverHello->getHandshakeVersion().toString();

                if (auto cs = serverHello->getCipherSuite())
                    msg_json["cipher_suites"] = json::array({ cs->asString() });
                else
                    msg_json["cipher_suites"] = json::array();

                msg_json["sni"] = nullptr; // ServerHello는 SNI가 없음
            }

            messages.push_back(msg_json);
        }

        j["messages"] = messages;
    }
    else if (dynamic_cast<const pcpp::SSLAlertLayer*>(sslLayer)) {
        j["type"] = "Alert";
    }
    else if (dynamic_cast<const pcpp::SSLApplicationDataLayer*>(sslLayer)) {
        j["type"] = "Application Data";
    }
    else if (dynamic_cast<const pcpp::SSLChangeCipherSpecLayer*>(sslLayer)) {
        j["type"] = "Change Cipher Spec";
    }

    return j;
}



    json parsePayloadLayer(const pcpp::PayloadLayer* payloadLayer) {
        json j;
        if (!payloadLayer) return j;
        j["size"] = payloadLayer->getPayloadLen();
        
        // 페이로드 일부(최대 64바이트)를 16진수 문자열로 표현
        size_t len_to_print = std::min((size_t)64, payloadLayer->getPayloadLen());
        j["data_hex_preview"] = helpers::bytesToHexString(payloadLayer->getPayload(), len_to_print);
        
        return j;
    }
    
    // --- 메인 파싱 함수 ---
    
    /**
     * @brief PcapPlusPlus Packet 객체를 분석하여 모든 레이어 정보를 JSON 객체로 변환합니다.
     * @param packet 분석할 pcpp::Packet 객체.
     * @return 패킷의 모든 레이어 정보가 담긴 nlohmann::json 객체.
     */
    json packetToJson(const pcpp::Packet& packet)
    {
        json result = json::object();
        
        // 패킷 메타데이터 추가
        result["timestamp_sec"] = packet.getRawPacket()->getPacketTimeStamp().tv_sec;
        result["timestamp_nsec"] = packet.getRawPacket()->getPacketTimeStamp().tv_nsec;
        result["total_length"] = packet.getRawPacket()->getRawDataLen();

        for (pcpp::Layer* currentLayer = packet.getFirstLayer(); currentLayer != nullptr; currentLayer = currentLayer->getNextLayer())
        {
            switch (currentLayer->getProtocol())
            {
                case pcpp::Ethernet:
                    result["ethernet"] = parseEthLayer(dynamic_cast<const pcpp::EthLayer*>(currentLayer));
                    break;
                case pcpp::ARP:
                    result["arp"] = parseArpLayer(dynamic_cast<const pcpp::ArpLayer*>(currentLayer));
                    break;
                case pcpp::IPv4:
                    result["ip"] = parseIPv4Layer(dynamic_cast<const pcpp::IPv4Layer*>(currentLayer));
                    break;
                case pcpp::IPv6:
                    result["ipv6"] = parseIPv6Layer(dynamic_cast<const pcpp::IPv6Layer*>(currentLayer));
                    break;
                case pcpp::TCP:
                    result["tcp"] = parseTcpLayer(dynamic_cast<const pcpp::TcpLayer*>(currentLayer));
                    break;
                case pcpp::UDP:
                    result["udp"] = parseUdpLayer(dynamic_cast<const pcpp::UdpLayer*>(currentLayer));
                    break;
                case pcpp::ICMP:
                    result["icmp"] = parseIcmpLayer(dynamic_cast<const pcpp::IcmpLayer*>(currentLayer));
                    break;
                case pcpp::DNS:
                    result["dns"] = parseDnsLayer(dynamic_cast<const pcpp::DnsLayer*>(currentLayer));
                    break;
                case pcpp::HTTPRequest:
                case pcpp::HTTPResponse:
                    // HTTP는 여러 패킷에 걸쳐 전송될 수 있으므로, 이미 키가 있다면 배열로 만듦
                    if (!result.contains("http")) {
                        result["http"] = json::array();
                    }
                    result["http"].push_back(parseHttpLayer(currentLayer));
                    break;
                case pcpp::SSL:
                    // SSL/TLS도 여러 레코드가 올 수 있으므로 배열 처리
                    if (!result.contains("tls")) {
                        result["tls"] = json::array();
                    }
                    result["tls"].push_back(parseSSLLayer(dynamic_cast<const pcpp::SSLLayer*>(currentLayer)));
                    break;
                case pcpp::GenericPayload:
                    result["payload"] = parsePayloadLayer(dynamic_cast<const pcpp::PayloadLayer*>(currentLayer));
                    break;
                case pcpp::SSH:
                    result["ssh"] = parseSSHLayer(dynamic_cast<const pcpp::SSHLayer*>(currentLayer));
                    break;
                default:
                    break;
            }
        }
        return result;
    }

} // namespace PacketParser

#endif // PACKET_TO_JSON_HPP