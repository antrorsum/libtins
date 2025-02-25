/*
 * Copyright (c) 2017, Matias Fontanini
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 * * Redistributions of source code must retain the above copyright
 *   notice, this list of conditions and the following disclaimer.
 * * Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the following disclaimer
 *   in the documentation and/or other materials provided with the
 *   distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#include <cstring>
#include <tins/macros.h>
#ifndef _WIN32
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        #include <net/if_dl.h>
    #else
        #include <netpacket/packet.h>
    #endif
    #include <netinet/in.h>
    #include <net/ethernet.h>
#endif
#include <tins/ethernetII.h>
#include <tins/config.h>
#include <tins/packet_sender.h>
#include <tins/pppoe.h>
#include <tins/constants.h>
#include <tins/exceptions.h>
#include <tins/memory_helpers.h>
#include <tins/detail/pdu_helpers.h>

using Tins::Memory::InputMemoryStream;
using Tins::Memory::OutputMemoryStream;

namespace Tins {

const EthernetII::address_type EthernetII::BROADCAST("ff:ff:ff:ff:ff:ff");

PDU::metadata EthernetII::extract_metadata(const uint8_t *buffer, uint32_t total_sz) {
    if (TINS_UNLIKELY(total_sz < sizeof(ethernet_header))) {
        throw malformed_packet();
    }
    const auto* header = (const ethernet_header*)buffer;
    PDUType next_type = Internals::ether_type_to_pdu_flag(
        static_cast<Constants::Ethernet::e>(Endian::be_to_host(header->payload_type)));
    return {sizeof(ethernet_header), pdu_flag, next_type}; 
}

EthernetII::EthernetII(const address_type& dst_hw_addr, 
                       const address_type& src_hw_addr) 
: header_() {
    dst_addr(dst_hw_addr);
    src_addr(src_hw_addr);
}

EthernetII::EthernetII(const uint8_t* buffer, uint32_t total_sz) {
    InputMemoryStream stream(buffer, total_sz);
    stream.read(header_);
    // If there's any size left
    if (stream) {
        inner_pdu(
            Internals::pdu_from_flag(
                (Constants::Ethernet::e)payload_type(), 
                stream.pointer(), 
                stream.size()
            )
        );
    }
}

void EthernetII::dst_addr(const address_type& new_dst_addr) {
    new_dst_addr.copy(header_.dst_mac);
}

void EthernetII::src_addr(const address_type& new_src_addr) {
    new_src_addr.copy(header_.src_mac);
}

void EthernetII::payload_type(uint16_t new_payload_type) {
    header_.payload_type = Endian::host_to_be(new_payload_type);
}

uint32_t EthernetII::header_size() const {
    return sizeof(header_);
}

uint32_t EthernetII::trailer_size() const {
    int32_t padding = 60 - sizeof(header_); // EthernetII min size is 60, padding is sometimes needed
    if (inner_pdu()) {
        padding -= inner_pdu()->size();
        padding = padding > 0 ? padding : 0;
    }
    return padding;
}

void EthernetII::send(PacketSender& sender, const NetworkInterface& iface) {
    if (!iface) {
        throw invalid_interface();
    }
    // Sending using pcap_sendpacket/BSD bpf packet mode is the same here
    sender.send_l2(*this, nullptr, 0, iface);
}

bool EthernetII::matches_response(const uint8_t* ptr, uint32_t total_sz) const {
    if (total_sz < sizeof(header_)) {
        return false;
    }
    const auto* eth_ptr = (const ethernet_header*)ptr;
    if (address_type(header_.src_mac) == address_type(eth_ptr->dst_mac)) {
        if (address_type(header_.src_mac) == address_type(eth_ptr->dst_mac) || 
           !dst_addr().is_unicast()) {
            return inner_pdu() ? 
                   inner_pdu()->matches_response(ptr + sizeof(header_), total_sz - sizeof(header_)) : 
                   true;
        }
    }
    return false;
}

void EthernetII::write_serialization(uint8_t* buffer, uint32_t total_sz) {
    OutputMemoryStream stream(buffer, total_sz);
    if (inner_pdu()) {
        Constants::Ethernet::e flag;
        const PDUType type = inner_pdu()->pdu_type();
        // Dirty trick to successfully tag PPPoE session/discovery packets
        if (type == PDU::PPPOE) {
            const auto* pppoe = static_cast<const PPPoE*>(inner_pdu());
            flag = (pppoe->code() == 0) ? Constants::Ethernet::PPPOES 
                                        : Constants::Ethernet::PPPOED;
        }
        // Dirty trick: Double Dot1Q is interpreted as Dot1AD
        else if (type == PDU::DOT1Q) {
            flag = Internals::pdu_flag_to_ether_type(type);

            if (inner_pdu()->inner_pdu()) {
                const PDUType inner_type = inner_pdu()->inner_pdu()->pdu_type();
                if (inner_type == PDU::DOT1Q) {
                    flag = Constants::Ethernet::QINQ;
                }
            }
        }
        else {
            flag = Internals::pdu_flag_to_ether_type(type);
        }
        if (flag != Constants::Ethernet::UNKNOWN) {
            payload_type(static_cast<uint16_t>(flag));
        }
    }
    else {
        payload_type(Constants::Ethernet::UNKNOWN);
    }
    stream.write(header_);
    const uint32_t trailer = trailer_size();
    if (trailer) {
        if (inner_pdu()) {
            stream.skip(inner_pdu()->size());
        }
        stream.fill(trailer, 0);
    }

}

#ifndef _WIN32
PDU* EthernetII::recv_response(PacketSender& sender, const NetworkInterface& iface) {
    #if !defined(BSD) && !defined(__FreeBSD_kernel__)
        struct sockaddr_ll addr;
        memset(&addr, 0, sizeof(struct sockaddr_ll));

        addr.sll_family = Endian::host_to_be<uint16_t>(PF_PACKET);
        addr.sll_protocol = Endian::host_to_be<uint16_t>(ETH_P_ALL);
        addr.sll_halen = address_type::address_size;
        addr.sll_ifindex = iface.id();
        memcpy(&(addr.sll_addr), header_.dst_mac, address_type::address_size);

        return sender.recv_l2(*this, (struct sockaddr*)&addr, (uint32_t)sizeof(addr));
    #else
        return sender.recv_l2(*this, 0, 0, iface);
    #endif
}
#endif // _WIN32

} // Tins
