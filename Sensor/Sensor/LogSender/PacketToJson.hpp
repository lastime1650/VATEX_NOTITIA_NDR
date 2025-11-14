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

        std::string sipMethodToString(pcpp::SipRequestLayer::SipMethod method) {
            switch (method) {
                case pcpp::SipRequestLayer::SipINVITE:    return "INVITE";
                case pcpp::SipRequestLayer::SipACK:       return "ACK";
                case pcpp::SipRequestLayer::SipBYE:       return "BYE";
                case pcpp::SipRequestLayer::SipCANCEL:    return "CANCEL";
                case pcpp::SipRequestLayer::SipREGISTER:  return "REGISTER";
                // ... (필요에 따라 다른 메서드 추가) ...
                default:                                  return "Unknown";
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

    json parseVlanLayer(const pcpp::VlanLayer* vlanLayer) {
        json j;
        if (!vlanLayer) return j;
        j["vlan_id"] = vlanLayer->getVlanID();
        j["priority"] = vlanLayer->getPriority();
        j["dei"] = vlanLayer->getCFI(); // CFI is now DEI
        return j;
    }

    json parseSllLayer(const pcpp::SllLayer* sllLayer) {
        json j;
        if (!sllLayer) return j;
        const pcpp::sll_header* hdr = sllLayer->getSllHeader();
        j["packet_type"] = ntohs(hdr->packet_type);
        j["arphrd_type"] = ntohs(hdr->ARPHRD_type);
        j["link_layer_addr_len"] = ntohs(hdr->link_layer_addr_len);
        if (ntohs(hdr->link_layer_addr_len) > 0) {
            j["link_layer_addr"] = helpers::bytesToHexString(hdr->link_layer_addr, ntohs(hdr->link_layer_addr_len));
        }
        return j;
    }

    json parseNullLoopbackLayer(const pcpp::NullLoopbackLayer* nullLayer) {
        json j;
        if (!nullLayer) return j;
        j["family"] = nullLayer->getFamily();
        return j;
    }

    json parsePPPoELayer(const pcpp::Layer* pppoeLayer) {
        json j;
        if (!pppoeLayer) return j;

        if (auto session = dynamic_cast<const pcpp::PPPoESessionLayer*>(pppoeLayer)) {
            j["type"] = "Session";
            j["version"] = static_cast<int>( session->getPPPoEHeader()->version );
            j["session_id"] = ntohs(session->getPPPoEHeader()->sessionId);
            j["ppp_protocol"] = session->getPPPNextProtocol();
        } else if (auto discovery = dynamic_cast<const pcpp::PPPoEDiscoveryLayer*>(pppoeLayer)) {
            j["type"] = "Discovery";
            j["version"] = static_cast<int>( discovery->getPPPoEHeader()->version );
            j["code"] = discovery->getPPPoEHeader()->code;
            j["session_id"] = ntohs(discovery->getPPPoEHeader()->sessionId);
        }
        return j;
    }

    json parseVxlanLayer(const pcpp::VxlanLayer* vxlanLayer) {
        json j;
        if (!vxlanLayer) return j;
        j["vni"] = vxlanLayer->getVNI();
        return j;
    }

    json parseMplsLayer(const pcpp::MplsLayer* mplsLayer) {
        json j;
        if (!mplsLayer) return j;
        j["label"] = mplsLayer->getMplsLabel();
        j["ttl"] = mplsLayer->getTTL();
        j["experimental_use"] = mplsLayer->getExperimentalUseValue();
        j["is_bottom_of_stack"] = mplsLayer->isBottomOfStack();
        return j;
    }

    json parseGreLayer(const pcpp::GreLayer* greLayer) {
        json j;
        if (!greLayer) return j;
        uint32_t seq, ack;

        if (auto grev0 = dynamic_cast<const pcpp::GREv0Layer*>(greLayer)) {
            j["version"] = 0;
            if (grev0->getSequenceNumber(seq)) j["sequence_number"] = seq;
        } else if (auto grev1 = dynamic_cast<const pcpp::GREv1Layer*>(greLayer)) {
            j["version"] = 1;
            if (grev1->getSequenceNumber(seq)) j["sequence_number"] = seq;
            if (grev1->getAcknowledgmentNum(ack)) j["ack_number"] = ack;
        }
        return j;
    }

    json parseIcmpV6Layer(const pcpp::IcmpV6Layer* icmpv6Layer) {
        json j;
        if (!icmpv6Layer) return j;
        auto msgType = icmpv6Layer->getMessageType();
        j["type"] = static_cast<int>(msgType);
        j["code"] = icmpv6Layer->getCode();

        // NDP 메시지인 경우 추가 정보 파싱
        if (msgType == pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION || msgType == pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT) {
            if (icmpv6Layer->getDataLen() >= 24)
            {
                // IcmpV6Layer의 데이터 시작점에서 8바이트 떨어진 위치에서 IPv6 주소를 생성합니다.
                pcpp::IPv6Address targetAddr(icmpv6Layer->getData() + 8);
                j["ndp_target_address"] = targetAddr.toString();
            }
        }
        return j;
    }

    json parseVrrpLayer(const pcpp::VrrpLayer* vrrpLayer) {
        json j;
        if (!vrrpLayer) return j;
        j["version"] = vrrpLayer->getVersion();
        j["type"] = vrrpLayer->getType();
        j["vrid"] = vrrpLayer->getVirtualRouterID();
        j["priority"] = vrrpLayer->getPriority();
        json ip_addrs = json::array();
        for (const auto& ip : vrrpLayer->getIPAddresses()) {
            ip_addrs.push_back(ip.toString());
        }
        j["ip_addresses"] = ip_addrs;
        return j;
    }

    json parseWireGuardLayer(const pcpp::WireGuardLayer* wgLayer) {
        json j;
        if (!wgLayer) return j;
        j["message_type_str"] = wgLayer->getMessageTypeAsString();
        
        if (auto init = dynamic_cast<const pcpp::WireGuardHandshakeInitiationLayer*>(wgLayer)) {
            j["sender_index"] = init->getSenderIndex();
        } else if (auto resp = dynamic_cast<const pcpp::WireGuardHandshakeResponseLayer*>(wgLayer)) {
            j["sender_index"] = resp->getSenderIndex();
            j["receiver_index"] = resp->getReceiverIndex();
        } else if (auto cookie = dynamic_cast<const pcpp::WireGuardCookieReplyLayer*>(wgLayer)) {
            j["receiver_index"] = cookie->getReceiverIndex();
        } else if (auto data = dynamic_cast<const pcpp::WireGuardTransportDataLayer*>(wgLayer)) {
            j["receiver_index"] = data->getReceiverIndex();
            j["counter"] = data->getCounter();
        }
        return j;
    }

    json parseIPSecLayer(const pcpp::Layer* ipsecLayer) {
        json j;
        if (!ipsecLayer) return j;

        if (auto ah = dynamic_cast<const pcpp::AuthenticationHeaderLayer*>(ipsecLayer)) {
            j["type"] = "AH";
            j["spi"] = ah->getSPI();
            j["sequence_number"] = ah->getSequenceNumber();
        } else if (auto esp = dynamic_cast<const pcpp::ESPLayer*>(ipsecLayer)) {
            j["type"] = "ESP";
            j["spi"] = esp->getSPI();
            j["sequence_number"] = esp->getSequenceNumber();
        }
        return j;
    }

    json parseGtpLayer(const pcpp::Layer* gtpLayer) {
        json j;
        if (!gtpLayer) return j;
        if (auto gtpv1 = dynamic_cast<const pcpp::GtpV1Layer*>(gtpLayer)) {
            j["version"] = 1;
            j["message_type"] = gtpv1->getMessageTypeAsString();
            j["teid"] = ntohl(gtpv1->getHeader()->teid);
        } else if (auto gtpv2 = dynamic_cast<const pcpp::GtpV2Layer*>(gtpLayer)) {
            j["version"] = 2;
            j["message_type"] = gtpv2->getMessageType().toString();
            auto teid_pair = gtpv2->getTeid();
            if (teid_pair.first) {
                j["teid"] = teid_pair.second;
            }
        }
        return j;
    }

    json parseSipLayer(const pcpp::Layer* sipLayer) {
        json j;
        if (!sipLayer) return j;
        if (auto req = dynamic_cast<const pcpp::SipRequestLayer*>(sipLayer)) {
            j["type"] = "request";
            j["method"] = helpers::sipMethodToString(req->getFirstLine()->getMethod());
            j["uri"] = req->getFirstLine()->getUri();
        } else if (auto res = dynamic_cast<const pcpp::SipResponseLayer*>(sipLayer)) {
            j["type"] = "response";
            j["status_code"] = res->getFirstLine()->getStatusCodeAsInt();
            j["reason_phrase"] = res->getFirstLine()->getStatusCodeString();
        }
        return j;
    }

    json parseDhcpLayer(const pcpp::DhcpLayer* dhcpLayer) {
        json j;
        if (!dhcpLayer) return j;
        j["op_code"] = dhcpLayer->getDhcpHeader()->opCode;
        j["message_type"] = dhcpLayer->getMessageType();
        j["client_ip"] = dhcpLayer->getClientIpAddress().toString();
        j["your_ip"] = dhcpLayer->getYourIpAddress().toString();
        j["server_ip"] = dhcpLayer->getServerIpAddress().toString();
        j["client_mac"] = dhcpLayer->getClientHardwareAddress().toString();
        return j;
    }

    json parseFtpLayer(const pcpp::Layer* ftpLayer) {
        json j;
        if (!ftpLayer) return j;
        if (auto req = dynamic_cast<const pcpp::FtpRequestLayer*>(ftpLayer)) {
            j["type"] = "request";
            j["command"] = req->getCommandString();
            j["option"] = req->getCommandOption();
        } else if (auto res = dynamic_cast<const pcpp::FtpResponseLayer*>(ftpLayer)) {
            j["type"] = "response";
            j["status_code"] = static_cast<int>(res->getStatusCode());
            j["message"] = res->getStatusOption();
        }
        return j;
    }

    json parseTelnetLayer(const pcpp::TelnetLayer* telnetLayer) {
        json j;
        if (!telnetLayer) return j;
        j["data"] = const_cast<pcpp::TelnetLayer*>(telnetLayer)->getDataAsString();
        return j;
    }

    json parseNtpLayer(const pcpp::NtpLayer* ntpLayer) {
        json j;
        if (!ntpLayer) return j;
        j["version"] = ntpLayer->getVersion();
        j["mode"] = ntpLayer->getModeString();
        j["stratum"] = ntpLayer->getStratum();
        j["leap_indicator"] = ntpLayer->getLeapIndicator();
        j["reference_id"] = ntpLayer->getReferenceIdentifierString();
        return j;
    }

    json parseRadiusLayer(const pcpp::RadiusLayer* radiusLayer) {
        json j;
        if (!radiusLayer) return j;
        j["code"] = radiusLayer->getRadiusHeader()->code;
        j["id"] = radiusLayer->getRadiusHeader()->id;
        // Attributes require iteration, which can be complex.
        // For simplicity, we only parse the header here.
        return j;
    }
    
     json parseLdapLayer(const pcpp::LdapLayer* ldapLayer) {
        json j;
        if (!ldapLayer) return j;
        auto nonConstLdap = const_cast<pcpp::LdapLayer*>(ldapLayer);
        uint16_t msgId;
        if (nonConstLdap->tryGet(&pcpp::LdapLayer::getMessageID, msgId)) {
            j["message_id"] = msgId;
        }
        pcpp::LdapOperationType opType;
        if (nonConstLdap->tryGet(&pcpp::LdapLayer::getLdapOperationType, opType)) {
            j["operation"] = opType.toString();
        }
        return j;
    }

    json parseBgpLayer(const pcpp::BgpLayer* bgpLayer) {
        json j;
        if (!bgpLayer) return j;
        j["type"] = bgpLayer->getMessageTypeAsString();

        if (auto openMsg = dynamic_cast<const pcpp::BgpOpenMessageLayer*>(bgpLayer)) {
            j["version"] = openMsg->getOpenMsgHeader()->version;
            j["my_as"] = ntohs(openMsg->getOpenMsgHeader()->myAutonomousSystem);
            j["hold_time"] = ntohs(openMsg->getOpenMsgHeader()->holdTime);
            j["bgp_id"] = openMsg->getBgpId().toString();
        }
        else if (auto updateMsg = dynamic_cast<const pcpp::BgpUpdateMessageLayer*>(bgpLayer)) {
            // Withdrawn routes and NLRI are complex; showing counts for simplicity
            j["withdrawn_routes_len"] = updateMsg->getWithdrawnRoutesLength();
            j["path_attributes_len"] = updateMsg->getPathAttributesLength();
            j["nlri_len"] = updateMsg->getNetworkLayerReachabilityInfoLength();
        }
        else if (auto notifMsg = dynamic_cast<const pcpp::BgpNotificationMessageLayer*>(bgpLayer)) {
            j["error_code"] = notifMsg->getNotificationMsgHeader()->errorCode;
            j["error_subcode"] = notifMsg->getNotificationMsgHeader()->errorSubCode;
        }
        else if (auto refreshMsg = dynamic_cast<const pcpp::BgpRouteRefreshMessageLayer*>(bgpLayer)) {
            j["afi"] = ntohs(refreshMsg->getRouteRefreshHeader()->afi);
            j["safi"] = refreshMsg->getRouteRefreshHeader()->safi;
        }
        // Keepalive has no extra fields
        
        return j;
    }

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
                // --- OSI Layer 2-3 ---
                case pcpp::Ethernet: result["ethernet"] = parseEthLayer(dynamic_cast<const pcpp::EthLayer*>(currentLayer)); break;
                case pcpp::SLL: result["sll"] = parseSllLayer(dynamic_cast<const pcpp::SllLayer*>(currentLayer)); break;
                case pcpp::NULL_LOOPBACK: result["null_loopback"] = parseNullLoopbackLayer(dynamic_cast<const pcpp::NullLoopbackLayer*>(currentLayer)); break;
                case pcpp::VLAN: result["vlan"] = parseVlanLayer(dynamic_cast<const pcpp::VlanLayer*>(currentLayer)); break;
                case pcpp::ARP: result["arp"] = parseArpLayer(dynamic_cast<const pcpp::ArpLayer*>(currentLayer)); break;
                case pcpp::IPv4: result["ip"] = parseIPv4Layer(dynamic_cast<const pcpp::IPv4Layer*>(currentLayer)); break;
                case pcpp::IPv6: result["ipv6"] = parseIPv6Layer(dynamic_cast<const pcpp::IPv6Layer*>(currentLayer)); break;
                
                // --- OSI Layer 4 ---
                case pcpp::TCP: result["tcp"] = parseTcpLayer(dynamic_cast<const pcpp::TcpLayer*>(currentLayer)); break;
                case pcpp::UDP: result["udp"] = parseUdpLayer(dynamic_cast<const pcpp::UdpLayer*>(currentLayer)); break;
                case pcpp::ICMP: result["icmp"] = parseIcmpLayer(dynamic_cast<const pcpp::IcmpLayer*>(currentLayer)); break;
                case pcpp::ICMPv6: result["icmpv6"] = parseIcmpV6Layer(dynamic_cast<const pcpp::IcmpV6Layer*>(currentLayer)); break;

                // --- Tunneling & Encapsulation ---
                case pcpp::PPPoESession:
                case pcpp::PPPoEDiscovery:
                    result["pppoe"] = parsePPPoELayer(currentLayer); break;
                case pcpp::VXLAN: result["vxlan"] = parseVxlanLayer(dynamic_cast<const pcpp::VxlanLayer*>(currentLayer)); break;
                case pcpp::MPLS:
                    if (!result.contains("mpls")) result["mpls"] = json::array();
                    result["mpls"].push_back(parseMplsLayer(dynamic_cast<const pcpp::MplsLayer*>(currentLayer)));
                    break;
                case pcpp::GREv0:
                case pcpp::GREv1:
                    result["gre"] = parseGreLayer(dynamic_cast<const pcpp::GreLayer*>(currentLayer)); break;
                case pcpp::AuthenticationHeader: // Correct enum for IPSec AH
                case pcpp::ESP:                  // Correct enum for IPSec ESP
                    result["ipsec"] = parseIPSecLayer(currentLayer); break;
                case pcpp::GTPv1:
                case pcpp::GTPv2:
                    result["gtp"] = parseGtpLayer(currentLayer); break;
                case pcpp::WireGuard: result["wireguard"] = parseWireGuardLayer(dynamic_cast<const pcpp::WireGuardLayer*>(currentLayer)); break;
                
                // --- OSI Layer 7 (Application) ---
                case pcpp::HTTPRequest:
                case pcpp::HTTPResponse:
                    if (!result.contains("http")) result["http"] = json::array();
                    result["http"].push_back(parseHttpLayer(currentLayer));
                    break;
                case pcpp::SSL:
                    if (!result.contains("tls")) result["tls"] = json::array();
                    result["tls"].push_back(parseSSLLayer(dynamic_cast<const pcpp::SSLLayer*>(currentLayer)));
                    break;
                case pcpp::SSH: result["ssh"] = parseSSHLayer(dynamic_cast<const pcpp::SSHLayer*>(currentLayer)); break;
                case pcpp::DNS: result["dns"] = parseDnsLayer(dynamic_cast<const pcpp::DnsLayer*>(currentLayer)); break;
                case pcpp::DHCP: result["dhcp"] = parseDhcpLayer(dynamic_cast<const pcpp::DhcpLayer*>(currentLayer)); break;
                case pcpp::SIPRequest:
                case pcpp::SIPResponse:
                    result["sip"] = parseSipLayer(currentLayer); break;
                case pcpp::FTPControl: // Use FTPControl for request/response
                    result["ftp"] = parseFtpLayer(currentLayer); break;
                case pcpp::Telnet: result["telnet"] = parseTelnetLayer(dynamic_cast<const pcpp::TelnetLayer*>(currentLayer)); break;
                case pcpp::NTP: result["ntp"] = parseNtpLayer(dynamic_cast<const pcpp::NtpLayer*>(currentLayer)); break;
                case pcpp::Radius: result["radius"] = parseRadiusLayer(dynamic_cast<const pcpp::RadiusLayer*>(currentLayer)); break;
                case pcpp::LDAP: result["ldap"] = parseLdapLayer(dynamic_cast<const pcpp::LdapLayer*>(currentLayer)); break;
                case pcpp::BGP: result["bgp"] = parseBgpLayer(dynamic_cast<const pcpp::BgpLayer*>(currentLayer)); break;

                // --- Other Protocols ---
                case pcpp::VRRPv2: // VRRP is split into v2 and v3
                case pcpp::VRRPv3:
                    result["vrrp"] = parseVrrpLayer(dynamic_cast<const pcpp::VrrpLayer*>(currentLayer)); break;
                
                // --- Payload/Trailer ---
                case pcpp::GenericPayload:
                case pcpp::FTPData: // FTPData is essentially a payload
                    result["payload"] = parsePayloadLayer(dynamic_cast<const pcpp::PayloadLayer*>(currentLayer));
                    break;
                default:
                    break;
            }
        }
        return result;
    }

} // namespace PacketParser

#endif // PACKET_TO_JSON_HPP