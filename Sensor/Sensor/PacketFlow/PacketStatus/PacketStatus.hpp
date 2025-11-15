#ifndef PktStatus_HPP
#define PktStatus_HPP

#include "../../../util/util.hpp"


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

namespace NDR
{
    namespace Sensor
    {
        namespace PacketStatus
        {
            // Parent
            class PacketStatusProtocol
            {
                public:
                    PacketStatusProtocol() = default;
                    virtual bool AppendPacket(const pcpp::Packet& Packet) = 0; // Input
                    virtual json ToJson() const = 0;
            };

            // ====================================================================
            // 기존 프로토콜 클래스들 (변경 없음)
            // ====================================================================

            // 2 Layer
            //// Ethernet
            class PacketStatusProtocol__ETHERNET : public PacketStatusProtocol
            {
            public:

                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* ethLayer = packet.getLayerOfType<pcpp::EthLayer>();
                    if (!ethLayer) return false;

                    count++;
                    if (ethLayer->getDestMac().toString() == "ff:ff:ff:ff:ff:ff") {
                        is_broadcast = 1;
                    }
                    return true;
                }

                json ToJson() const override {
                    json j = json::object();
                    j["eth_count"] = count;
                    j["eth_has_broadcast"] = is_broadcast;
                    return j;
                }

            private:
                uint64_t count = 0;
                int is_broadcast = 0;
            };

            // Layer 3: IPv4
            class PacketStatusProtocol__IPV4 : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__IPV4() = default;

                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* ipLayer = packet.getLayerOfType<pcpp::IPv4Layer>();
                    if (!ipLayer) return false;

                    count++;
                    if (ipLayer->isFragment()) {
                        fragment_count++;
                    }
                    return true;
                }

                json ToJson() const override {
                    json j = json::object();
                    j["ipv4_count"] = count;
                    j["ipv4_fragment_count"] = fragment_count;
                    return j;
                }

            private:
                uint64_t count = 0;
                uint64_t fragment_count = 0;
            };

            // Layer 4: TCP
            class PacketStatusProtocol__TCP : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__TCP() = default;

                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
                    if (!tcpLayer) return false;

                    count++;
                    const pcpp::tcphdr* hdr = tcpLayer->getTcpHeader();
                    if (hdr->synFlag) syn_count++;
                    if (hdr->ackFlag) ack_count++;
                    if (hdr->finFlag) fin_count++;
                    if (hdr->rstFlag) rst_count++;
                    if (hdr->pshFlag) psh_count++;
                    if (hdr->urgFlag) urg_count++;
                    payload_bytes += tcpLayer->getLayerPayloadSize();

                    return true;
                }

                json ToJson() const override {
                    json j = json::object();
                    j["tcp_count"] = count;
                    j["tcp_syn_count"] = syn_count;
                    j["tcp_ack_count"] = ack_count;
                    j["tcp_fin_count"] = fin_count;
                    j["tcp_rst_count"] = rst_count;
                    j["tcp_psh_count"] = psh_count;
                    j["tcp_urg_count"] = urg_count;
                    j["tcp_payload_bytes"] = payload_bytes;
                    return j;
                }

            private:
                uint64_t count = 0;
                uint64_t payload_bytes = 0;
                uint64_t syn_count = 0, ack_count = 0, fin_count = 0;
                uint64_t rst_count = 0, psh_count = 0, urg_count = 0;
            };

            // Layer 4: UDP
            class PacketStatusProtocol__UDP : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__UDP() = default;

                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
                    if (!udpLayer) return false;

                    count++;
                    payload_bytes += udpLayer->getLayerPayloadSize();
                    return true;
                }

                json ToJson() const override {
                    json j = json::object();
                    j["udp_count"] = count;
                    j["udp_payload_bytes"] = payload_bytes;
                    return j;
                }
            private:
                uint64_t count = 0;
                uint64_t payload_bytes = 0;
            };

            // Application Layer: HTTP
            class PacketStatusProtocol__HTTP : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__HTTP() = default;
            
                bool AppendPacket(const pcpp::Packet& packet) override {
                    bool found = false;
                    if (packet.getLayerOfType<pcpp::HttpRequestLayer>()) {
                        auto* req = packet.getLayerOfType<pcpp::HttpRequestLayer>();
                        found = true;
                        request_count++;
                        if (req->getFirstLine()->getMethod() == pcpp::HttpRequestLayer::HttpGET)
                            method_get_count++;
                        else if (req->getFirstLine()->getMethod() == pcpp::HttpRequestLayer::HttpPOST)
                            method_post_count++;
                    }
                    if (packet.getLayerOfType<pcpp::HttpResponseLayer>()) {
                        auto* res = packet.getLayerOfType<pcpp::HttpResponseLayer>();
                        found = true;
                        response_count++;
                        int code = res->getFirstLine()->getStatusCodeAsInt();
                        if (code >= 200 && code < 300)
                            status_2xx_count++;
                        else if (code >= 400 && code < 500)
                            status_4xx_count++;
                    }
                    return found;
                }

                json ToJson() const override {
                    json j = json::object();
                    j["http_request_count"] = request_count;
                    j["http_response_count"] = response_count;
                    j["http_get_count"] = method_get_count;
                    j["http_post_count"] = method_post_count;
                    j["http_status_2xx_count"] = status_2xx_count;
                    j["http_status_4xx_count"] = status_4xx_count;
                    
                    return j;
                }
            private:
                uint64_t request_count = 0, response_count = 0;
                uint64_t method_get_count = 0, method_post_count = 0;
                uint64_t status_2xx_count = 0, status_4xx_count = 0;
            };

             // Application Layer: DNS
            class PacketStatusProtocol__DNS : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__DNS() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* dnsLayer = packet.getLayerOfType<pcpp::DnsLayer>();
                    if (!dnsLayer) return false;

                    count++;
                    if (dnsLayer->getDnsHeader()->queryOrResponse != 0) {
                        has_response = 1; 
                    }
                    query_total += dnsLayer->getQueryCount();
                    answer_total += dnsLayer->getAnswerCount();
                    
                    return true;
                }

                json ToJson() const override {
                    json j = json::object();
                    j["dns_count"] = count;
                    j["dns_has_response"] = has_response;
                    j["dns_query_total"] = query_total;
                    j["dns_answer_total"] = answer_total;
                    return j;
                }
            private:
                uint64_t count = 0;
                int has_response = 0;
                uint64_t query_total = 0;
                uint64_t answer_total = 0;
            };

            // Layer 2.5: VLAN
            class PacketStatusProtocol__VLAN : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__VLAN() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::VlanLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["vlan_count"] = count;
                    return j;
                }
            private:
                uint64_t count = 0;
            };

            // Layer 2.5: PPPoE
            class PacketStatusProtocol__PPPOE : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__PPPOE() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* pppoeLayer = packet.getLayerOfType<pcpp::PPPoELayer>();
                    if (!pppoeLayer) return false;
                    
                    count++;
                    if (dynamic_cast<const pcpp::PPPoESessionLayer*>(pppoeLayer)) {
                        session_count++;
                    } else if (dynamic_cast<const pcpp::PPPoEDiscoveryLayer*>(pppoeLayer)) {
                        discovery_count++;
                    }
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["pppoe_count"] = count;
                    j["pppoe_session_count"] = session_count;
                    j["pppoe_discovery_count"] = discovery_count;
                    return j;
                }
            private:
                uint64_t count = 0;
                uint64_t session_count = 0;
                uint64_t discovery_count = 0;
            };
            
            // Layer 3: ARP
            class PacketStatusProtocol__ARP : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__ARP() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* arpLayer = packet.getLayerOfType<pcpp::ArpLayer>();
                    if (!arpLayer) return false;
                    
                    count++;
                    uint16_t opcode = ntohs(arpLayer->getArpHeader()->opcode);
                    if (opcode == 1) { // ARP_REQUEST
                        request_count++;
                    } else if (opcode == 2) { // ARP_REPLY
                        reply_count++;
                    }
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["arp_count"] = count;
                    j["arp_request_count"] = request_count;
                    j["arp_reply_count"] = reply_count;
                    
                    return j;
                }
            private:
                uint64_t count = 0;
                uint64_t request_count = 0;
                uint64_t reply_count = 0;
            };

            // Layer 3: IPv6
            class PacketStatusProtocol__IPV6 : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__IPV6() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* ipv6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
                    if (!ipv6Layer) return false;
                    
                    count++;
                    if (ipv6Layer->isFragment()) {
                        fragment_count++;
                    }
                    uint8_t nextHeader = ipv6Layer->getIPv6Header()->nextHeader;
                    switch (nextHeader) {
                        case 0: case 60: case 43: case 44: case 51: case 50: case 135:
                            ipv6_has_extension_header = 1;
                            break;
                        default: break;
                    }
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["ipv6_count"] = count;
                    j["ipv6_fragment_count"] = fragment_count;
                    j["ipv6_has_extension_header"] = ipv6_has_extension_header;
                    return j;
                }
            private:
                uint64_t count = 0;
                uint64_t fragment_count = 0;
                int ipv6_has_extension_header = 0;
            };
            
            // Layer 4: ICMP
            class PacketStatusProtocol__ICMP : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__ICMP() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* icmpLayer = packet.getLayerOfType<pcpp::IcmpLayer>();
                    if (!icmpLayer) return false;

                    count++;
                    uint8_t type = icmpLayer->getIcmpHeader()->type;
                    if (type == 8) echo_request_count++;
                    else if (type == 0) echo_reply_count++;
                    else if (type == 3) dest_unreachable_count++;
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["icmp_count"] = count;
                    j["icmp_echo_request_count"] = echo_request_count;
                    j["icmp_echo_reply_count"] = echo_reply_count;
                    j["icmp_dest_unreachable_count"] = dest_unreachable_count;
                    return j;
                }
            private:
                uint64_t count = 0;
                uint64_t echo_request_count = 0, echo_reply_count = 0, dest_unreachable_count = 0;
            };

            // Layer 4: ICMPv6
            class PacketStatusProtocol__ICMPV6 : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__ICMPV6() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* icmpv6Layer = packet.getLayerOfType<pcpp::IcmpV6Layer>();
                    if (!icmpv6Layer) return false;

                    count++;
                    auto msgType = icmpv6Layer->getMessageType();
                    if (msgType == pcpp::ICMPv6MessageType::ICMPv6_ECHO_REQUEST) echo_request_count++;
                    else if (msgType == pcpp::ICMPv6MessageType::ICMPv6_ECHO_REPLY) echo_reply_count++;
                    else if (msgType == pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_SOLICITATION) neighbor_solicitation_count++;
                    else if (msgType == pcpp::ICMPv6MessageType::ICMPv6_NEIGHBOR_ADVERTISEMENT) neighbor_advertisement_count++;
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["icmpv6_count"] = count;
                    j["icmpv6_echo_request_count"] = echo_request_count;
                    j["icmpv6_echo_reply_count"] = echo_reply_count;
                    j["icmpv6_neighbor_solicitation_count"] = neighbor_solicitation_count;
                    j["icmpv6_neighbor_advertisement_count"] = neighbor_advertisement_count;
                    return j;
                }
            private:
                uint64_t count = 0;
                uint64_t echo_request_count = 0, echo_reply_count = 0, neighbor_solicitation_count = 0, neighbor_advertisement_count = 0;
            };

            // Tunneling/Security: IPSec
            class PacketStatusProtocol__IPSEC : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__IPSEC() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    bool found = false;
                    if (packet.getLayerOfType<pcpp::AuthenticationHeaderLayer>()) {
                        ah_count++;
                        found = true;
                    }
                    if (packet.getLayerOfType<pcpp::ESPLayer>()) {
                        esp_count++;
                        found = true;
                    }
                    return found;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["ipsec_ah_count"] = ah_count;
                    j["ipsec_esp_count"] = esp_count;
                    return j;
                }
            private:
                uint64_t ah_count = 0, esp_count = 0;
            };

            // App Layer: SSH
            class PacketStatusProtocol__SSH : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__SSH() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* sshLayer = packet.getLayerOfType<pcpp::SSHLayer>();
                    if (!sshLayer) return false;

                    count++;
                    if (dynamic_cast<pcpp::SSHIdentificationMessage*>(sshLayer)) identification_count++;
                    else if (dynamic_cast<pcpp::SSHKeyExchangeInitMessage*>(const_cast<pcpp::SSHLayer*>(sshLayer))) kex_init_count++;
                    else if (dynamic_cast<const pcpp::SSHEncryptedMessage*>(sshLayer)) encrypted_count++;
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["ssh_count"] = count;
                    j["ssh_identification_count"] = identification_count;
                    j["ssh_kex_init_count"] = kex_init_count;
                    j["ssh_encrypted_count"] = encrypted_count;
                    return j;
                }
            private:
                uint64_t count = 0, identification_count = 0, kex_init_count = 0, encrypted_count = 0;
            };
            
            // App Layer: DHCP
            class PacketStatusProtocol__DHCP : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__DHCP() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* dhcpLayer = packet.getLayerOfType<pcpp::DhcpLayer>();
                    if (!dhcpLayer) return false;

                    count++;
                    auto msgType = dhcpLayer->getMessageType();
                    if (msgType == pcpp::DHCP_DISCOVER) discover_count++;
                    else if (msgType == pcpp::DHCP_OFFER) offer_count++;
                    else if (msgType == pcpp::DHCP_REQUEST) request_count++;
                    else if (msgType == pcpp::DHCP_ACK) ack_count++;
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["dhcp_count"] = count;
                    j["dhcp_discover_count"] = discover_count;
                    j["dhcp_offer_count"] = offer_count;
                    j["dhcp_request_count"] = request_count;
                    j["dhcp_ack_count"] = ack_count;
                    return j;
                }
            private:
                uint64_t count = 0;
                uint64_t discover_count = 0, offer_count = 0, request_count = 0, ack_count = 0;
            };

            // ====================================================================
            // 새로 추가된 프로토콜 클래스들
            // ====================================================================
            
            // App Layer: SSL/TLS
            class PacketStatusProtocol__SSL : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__SSL() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* sslLayer = packet.getLayerOfType<pcpp::SSLLayer>();
                    if (!sslLayer) return false;
                    
                    count++;
                    if (dynamic_cast<const pcpp::SSLHandshakeLayer*>(sslLayer)) handshake_count++;
                    else if (dynamic_cast<const pcpp::SSLAlertLayer*>(sslLayer)) alert_count++;
                    else if (dynamic_cast<const pcpp::SSLApplicationDataLayer*>(sslLayer)) app_data_count++;
                    else if (dynamic_cast<const pcpp::SSLChangeCipherSpecLayer*>(sslLayer)) change_cipher_spec_count++;
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["ssl_count"] = count;
                    j["ssl_handshake_count"] = handshake_count;
                    j["ssl_alert_count"] = alert_count;
                    j["ssl_app_data_count"] = app_data_count;
                    j["ssl_change_cipher_spec_count"] = change_cipher_spec_count;
                    return j;
                }
            private:
                uint64_t count = 0, handshake_count = 0, alert_count = 0, app_data_count = 0, change_cipher_spec_count = 0;
            };

            // App Layer: FTP
            class PacketStatusProtocol__FTP : public PacketStatusProtocol
            {
            public:
                PacketStatusProtocol__FTP() = default;
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* ftpLayer = packet.getLayerOfType<pcpp::FtpLayer>();
                    if (!ftpLayer) return false;
                    
                    count++;
                    if (dynamic_cast<const pcpp::FtpRequestLayer*>(ftpLayer)) request_count++;
                    else if (dynamic_cast<const pcpp::FtpResponseLayer*>(ftpLayer)) response_count++;
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["ftp_count"] = count;
                    j["ftp_request_count"] = request_count;
                    j["ftp_response_count"] = response_count;
                    return j;
                }
            private:
                uint64_t count = 0, request_count = 0, response_count = 0;
            };

            // App Layer: Telnet
            class PacketStatusProtocol__TELNET : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::TelnetLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"telnet_count", count}};
                }
            private:
                uint64_t count = 0;
            };

            // App Layer: BGP
            class PacketStatusProtocol__BGP : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* bgpLayer = packet.getLayerOfType<pcpp::BgpLayer>();
                    if (!bgpLayer) return false;

                    count++;
                    if (dynamic_cast<const pcpp::BgpOpenMessageLayer*>(bgpLayer)) open_count++;
                    else if (dynamic_cast<const pcpp::BgpUpdateMessageLayer*>(bgpLayer)) update_count++;
                    else if (dynamic_cast<const pcpp::BgpNotificationMessageLayer*>(bgpLayer)) notification_count++;
                    else if (dynamic_cast<const pcpp::BgpKeepaliveMessageLayer*>(bgpLayer)) keepalive_count++;
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["bgp_count"] = count;
                    j["bgp_open_count"] = open_count;
                    j["bgp_update_count"] = update_count;
                    j["bgp_notification_count"] = notification_count;
                    j["bgp_keepalive_count"] = keepalive_count;
                    return j;
                }
            private:
                uint64_t count = 0, open_count = 0, update_count = 0, notification_count = 0, keepalive_count = 0;
            };

            // App Layer: SIP
            class PacketStatusProtocol__SIP : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    auto* sipLayer = packet.getLayerOfType<pcpp::SipLayer>();
                    if (!sipLayer) return false;
                    
                    count++;
                    if (dynamic_cast<const pcpp::SipRequestLayer*>(sipLayer)) request_count++;
                    else if (dynamic_cast<const pcpp::SipResponseLayer*>(sipLayer)) response_count++;
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["sip_count"] = count;
                    j["sip_request_count"] = request_count;
                    j["sip_response_count"] = response_count;
                    return j;
                }
            private:
                uint64_t count = 0, request_count = 0, response_count = 0;
            };

            // App Layer: NTP
            class PacketStatusProtocol__NTP : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::NtpLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"ntp_count", count}};
                }
            private:
                uint64_t count = 0;
            };

            // App Layer: Radius
            class PacketStatusProtocol__RADIUS : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::RadiusLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"radius_count", count}};
                }
            private:
                uint64_t count = 0;
            };
            
            // App Layer: LDAP
            class PacketStatusProtocol__LDAP : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::LdapLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"ldap_count", count}};
                }
            private:
                uint64_t count = 0;
            };

            // Tunneling: GRE
            class PacketStatusProtocol__GRE : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::GreLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"gre_count", count}};
                }
            private:
                uint64_t count = 0;
            };

            // Tunneling: GTP
            class PacketStatusProtocol__GTP : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {

                    auto V1 = packet.getLayerOfType<pcpp::GtpV1Layer>();
                    auto V2 = packet.getLayerOfType<pcpp::GtpV2Layer>();
                    if(V1)
                    {
                        v1_count++;
                    }
                    
                    if (V2)
                    {
                        v2_count++;
                    }
                    else
                        return false;

                    count++;
                    
                    return true;
                }
                json ToJson() const override {
                    json j = json::object();
                    j["gtp_count"] = count;
                    j["gtp_v1_count"] = v1_count;
                    j["gtp_v2_count"] = v2_count;
                    return j;
                }
            private:
                uint64_t count = 0, v1_count = 0, v2_count = 0;
            };

            // Tunneling: VXLAN
            class PacketStatusProtocol__VXLAN : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::VxlanLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"vxlan_count", count}};
                }
            private:
                uint64_t count = 0;
            };

            // Layer 2.5: MPLS
            class PacketStatusProtocol__MPLS : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    bool foundMpls = false;
                    // 패킷의 첫 번째 레이어부터 마지막 레이어까지 순회합니다.
                    for (pcpp::Layer* currentLayer = packet.getFirstLayer(); currentLayer != nullptr; currentLayer = currentLayer->getNextLayer())
                    {
                        // 현재 레이어가 MplsLayer 타입인지 확인합니다.
                        if (currentLayer->getProtocol() == pcpp::MPLS) {
                            count++;
                            foundMpls = true;
                        }
                    }
                    return foundMpls;
                }
                json ToJson() const override {
                    return json{{"mpls_count", count}};
                }
            private:
                uint64_t count = 0;
            };

            // Other: VRRP
            class PacketStatusProtocol__VRRP : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::VrrpLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"vrrp_count", count}};
                }
            private:
                uint64_t count = 0;
            };

            // Tunneling/Security: WireGuard
            class PacketStatusProtocol__WIREGUARD : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::WireGuardLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"wireguard_count", count}};
                }
            private:
                uint64_t count = 0;
            };
            
            // Layer 2: SLL (Linux Cooked Capture)
            class PacketStatusProtocol__SLL : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::SllLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"sll_count", count}};
                }
            private:
                uint64_t count = 0;
            };

            // Layer 2: Null/Loopback
            class PacketStatusProtocol__NULL_LOOPBACK : public PacketStatusProtocol
            {
            public:
                bool AppendPacket(const pcpp::Packet& packet) override {
                    if (packet.getLayerOfType<pcpp::NullLoopbackLayer>()) {
                        count++;
                        return true;
                    }
                    return false;
                }
                json ToJson() const override {
                    return json{{"null_loopback_count", count}};
                }
            private:
                uint64_t count = 0;
            };


            // ====================================================================
            // 메인 클래스
            // ====================================================================
            class PacketStatus
            {
                public:
                    PacketStatus()
                    {
                        // --- 기본 프로토콜 ---
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__ETHERNET>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__IPV4>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__TCP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__UDP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__HTTP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__DNS>());

                        // --- 기존에 추가된 프로토콜 ---
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__VLAN>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__PPPOE>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__ARP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__IPV6>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__ICMP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__ICMPV6>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__IPSEC>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__SSH>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__DHCP>());

                        // --- 이번에 새로 추가된 프로토콜 ---
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__SSL>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__FTP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__TELNET>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__BGP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__SIP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__NTP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__RADIUS>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__LDAP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__GRE>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__GTP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__VXLAN>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__MPLS>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__VRRP>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__WIREGUARD>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__SLL>());
                        m_protocols.push_back(std::make_shared<PacketStatusProtocol__NULL_LOOPBACK>());
                    }
                    ~PacketStatus() = default;

                    bool AppendPacket(const pcpp::Packet& packet) {

                        for (auto& protocol_handler : m_protocols) {
                            protocol_handler->AppendPacket(packet);
                        }
                        return true;
                    }

                    json ToJson() const {
                        json final_json;

                        for (const auto& protocol_handler : m_protocols) {
                            final_json.update(protocol_handler->ToJson());
                        }
                        return final_json;
                    }

                private:
                     std::vector<std::shared_ptr<PacketStatusProtocol>> m_protocols;
            };


        }
    }
}

#endif