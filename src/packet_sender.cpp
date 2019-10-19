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

#include <arpa/inet.h>
#include <cerrno>
#include <cstring>
#include <ctime>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sstream>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <tins/macros.h>
#include <tins/packet_sender.h>
#include <tins/pdu.h>
#include <unistd.h>
// PDUs required by PacketSender::send(PDU&, NetworkInterface)
#include <tins/ethernetII.h>
#include <tins/radiotap.h>
#include <tins/dot11/dot11_base.h>
#include <tins/radiotap.h>
#include <tins/ieee802_3.h>
#include <tins/cxxstd.h>
#include <tins/detail/pdu_helpers.h>
#include <chrono>

using std::string;
using std::ostringstream;
using std::make_pair;
using std::vector;
using std::runtime_error;

namespace Tins {

const int PacketSender::INVALID_RAW_SOCKET = -1;
const uint32_t PacketSender::DEFAULT_TIMEOUT = 2;

#ifndef _WIN32
    using socket_type = int;
    
    const char* make_error_string() {
        return strerror(errno);
    }
#else
    typedef SOCKET socket_type;

    // fixme
    const char* make_error_string() {
        return "error";
    }
#endif

PacketSender::PacketSender(const NetworkInterface& iface, 
                           uint32_t recv_timeout, 
                           uint32_t usec) 
: sockets_(SOCKETS_END, INVALID_RAW_SOCKET), 
#if !defined(BSD) && !defined(_WIN32) && !defined(__FreeBSD_kernel__)
  ether_socket_(INVALID_RAW_SOCKET),
#endif
  _timeout(recv_timeout), timeout_usec_(usec), default_iface_(iface) {
    types_[IP_TCP_SOCKET] = IPPROTO_TCP;
    types_[IP_UDP_SOCKET] = IPPROTO_UDP;
    types_[IP_RAW_SOCKET] = IPPROTO_RAW;
    types_[IPV6_SOCKET] = IPPROTO_RAW;
    types_[ICMP_SOCKET] = IPPROTO_ICMP;
    types_[ICMPV6_SOCKET] = IPPROTO_ICMPV6;
}

PacketSender::~PacketSender() {
    for (int socket : sockets_) {
        if (socket != INVALID_RAW_SOCKET)  {
                ::close(socket);
        }
    }
    if (ether_socket_ != INVALID_RAW_SOCKET) {
        ::close(ether_socket_);
    }

    for (auto & pcap_handle : pcap_handles_) {
        pcap_close(pcap_handle.second);
    }
    pcap_handles_.clear();
}

void PacketSender::default_interface(const NetworkInterface& iface) {
    default_iface_ = iface;
}

const NetworkInterface& PacketSender::default_interface() const {
    return default_iface_;
}

bool PacketSender::ether_socket_initialized(const NetworkInterface& iface) const {
    #if defined(BSD) || defined(__FreeBSD_kernel__)
    return ether_socket_.count(iface.id());
    #else
    Internals::unused(iface);
    return ether_socket_ != INVALID_RAW_SOCKET;
    #endif
}

int PacketSender::get_ether_socket(const NetworkInterface& iface) {
    if (!ether_socket_initialized(iface)) {
        open_l2_socket(iface);
    }
    #if defined(BSD) || defined(__FreeBSD_kernel__)
    return ether_socket_[iface.id()];
    #else
    return ether_socket_;
    #endif
}

pcap_t* PacketSender::make_pcap_handle(const NetworkInterface& iface) const {
    // This is an ugly fix to make interface names look like what 
    // libpcap expects on Windows
    #ifdef _WIN32
        #define TINS_PREFIX_INTERFACE(x) ("\\Device\\NPF_" + x)
    #else // _WIN32
        #define TINS_PREFIX_INTERFACE(x) (x)
    #endif // _WIN32

    char error[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_create(TINS_PREFIX_INTERFACE(iface.name()).c_str(), error);
    if (!handle) {
        throw pcap_error("Error opening pcap handle: " + string(error));
    }
    if (pcap_set_promisc(handle, 1) < 0) {
        throw pcap_error("Failed to set pcap handle promisc mode: " + string(pcap_geterr(handle)));
    }
    if (pcap_activate(handle) < 0) {
        throw pcap_error("Failed to activate pcap handle: " + string(pcap_geterr(handle)));
    }
    return handle;
}

void PacketSender::open_l2_socket(const NetworkInterface& iface) {
    if (pcap_handles_.count(iface) == 0) {
        pcap_handles_.insert(make_pair(iface, make_pcap_handle(iface)));
    }
}

void PacketSender::open_l3_socket(SocketType type) {
    int socktype = find_type(type);
    if (socktype == -1) {
        throw invalid_socket_type();
    }
    if (sockets_[type] == INVALID_RAW_SOCKET) {
        const bool is_v6 = (type == IPV6_SOCKET || type == ICMPV6_SOCKET);
        socket_type sockfd;
        sockfd = socket(is_v6 ? AF_INET6 : AF_INET, SOCK_RAW, socktype);
        if (sockfd < 0) {
            throw socket_open_error(make_error_string());
        }

        const int on = 1;
        #ifndef _WIN32
        using option_ptr = const void *;
        #else
        typedef const char* option_ptr;
        #endif
        const int level = (is_v6) ? IPPROTO_IPV6 : IPPROTO_IP;
        if (setsockopt(sockfd, level, IP_HDRINCL, (option_ptr)&on, sizeof(on)) != 0) {
            throw socket_open_error(make_error_string());
        }

        sockets_[type] = static_cast<int>(sockfd);
    }
}

void PacketSender::close_socket(SocketType type, const NetworkInterface& iface) {
    if (type == ETHER_SOCKET) {
        #if defined(BSD) || defined(__FreeBSD_kernel__)
        BSDEtherSockets::iterator it = ether_socket_.find(iface.id());
        if (it == ether_socket_.end()) {
            throw invalid_socket_type();
        }
        if (::close(it->second) == -1) {
            throw socket_close_error(make_error_string());
        }
        ether_socket_.erase(it);
        #elif !defined(_WIN32)
        Internals::unused(iface);
        if (ether_socket_ == INVALID_RAW_SOCKET) {
            throw invalid_socket_type();
        }
        if (::close(ether_socket_) == -1) {
            throw socket_close_error(make_error_string());
        }
        ether_socket_ = INVALID_RAW_SOCKET;
        #endif
    }
    else {
        Internals::unused(iface);
        if (type >= SOCKETS_END || sockets_[type] == INVALID_RAW_SOCKET) {
            throw invalid_socket_type();
        }
        #ifndef _WIN32
        if (close(sockets_[type]) == -1) {
            throw socket_close_error(make_error_string());
        }
        #else
        closesocket(sockets_[type]);
        #endif
        sockets_[type] = INVALID_RAW_SOCKET;
    }
}

void PacketSender::send(PDU& pdu) {
    pdu.send(*this, default_iface_);
}

void PacketSender::send(PDU& pdu, const NetworkInterface& iface) {
    if (pdu.matches_flag(PDU::ETHERNET_II)) {
        send<Tins::EthernetII>(pdu, iface);
    }
    #ifdef TINS_HAVE_DOT11
        else if (pdu.matches_flag(PDU::DOT11)) {
            send<Tins::Dot11>(pdu, iface);
        }
        else if (pdu.matches_flag(PDU::RADIOTAP)) {
            send<Tins::RadioTap>(pdu, iface);
        }
    #endif // TINS_HAVE_DOT11
    else if (pdu.matches_flag(PDU::IEEE802_3)) {
        send<Tins::IEEE802_3>(pdu, iface);
    }
    else {
        send(pdu);
    }
}

PDU* PacketSender::send_recv(PDU& pdu) {
    return send_recv(pdu, default_iface_);
}

PDU* PacketSender::send_recv(PDU& pdu, const NetworkInterface& iface) {
    try {
        pdu.send(*this, iface);
    }
    catch (runtime_error&) {
        return 0;
    }
    return pdu.recv_response(*this, iface);
}

void PacketSender::send_l2(PDU& pdu,
                           struct sockaddr* link_addr, 
                           uint32_t len_addr,
                           const NetworkInterface& iface) {
    PDU::serialization_type buffer = pdu.serialize();

    Internals::unused(len_addr);
    Internals::unused(link_addr);
    open_l2_socket(iface);
    pcap_t* handle = pcap_handles_[iface];
    const int buf_size = static_cast<int>(buffer.size());
    if (pcap_sendpacket(handle, (u_char*)&buffer[0], buf_size) != 0) {
        throw pcap_error("Failed to send packet: " + string(pcap_geterr(handle)));
    }
}

PDU* PacketSender::recv_l2(PDU& pdu, 
                           struct sockaddr* link_addr, 
                           uint32_t len_addr,
                           const NetworkInterface& iface) {
    int sock = get_ether_socket(iface);
    vector<int> sockets(1, sock);
    return recv_match_loop(sockets, pdu, link_addr, len_addr, false);
}

PDU* PacketSender::recv_l3(PDU& pdu, 
                           struct sockaddr* link_addr,
                           uint32_t len_addr,
                           SocketType type) {
    open_l3_socket(type);
    vector<int> sockets(1, sockets_[type]);
    if (type == IP_TCP_SOCKET || type == IP_UDP_SOCKET) {
        #ifdef BSD
            throw feature_disabled();
        #endif
        open_l3_socket(ICMP_SOCKET);
        sockets.push_back(sockets_[ICMP_SOCKET]);
    }
    return recv_match_loop(sockets, pdu, link_addr, len_addr, true);
}

void PacketSender::send_l3(PDU& pdu, 
                           struct sockaddr* link_addr,
                           uint32_t len_addr,
                           SocketType type) {
    open_l3_socket(type);
    int sock = sockets_[type];
    PDU::serialization_type buffer = pdu.serialize();
    const int buf_size = static_cast<int>(buffer.size());
    if (sendto(sock, (const char*)&buffer[0], buf_size, 0, link_addr, len_addr) == -1) {
        throw socket_write_error(make_error_string());
    }
}

PDU* PacketSender::recv_match_loop(const vector<int>& sockets, 
                                   PDU& pdu,
                                   struct sockaddr* link_addr,
                                   uint32_t addrlen,
                                   bool is_layer_3) {
    #ifdef _WIN32
        typedef int socket_len_type;
        typedef int recvfrom_ret_type;
    #else
        using socket_len_type = socklen_t;
        using recvfrom_ret_type = ssize_t;
    #endif
    fd_set readfds;
    struct timeval timeout,  end_time;
    int read;
    #if defined(BSD) || defined(__FreeBSD_kernel__)
        bool is_bsd = true;
        // On* BSD, we need to allocate a buffer using the given size.
        const int buffer_size = is_layer_3 ? 2048 : buffer_size_;
        vector<uint8_t> actual_buffer(buffer_size);
        uint8_t* buffer = &actual_buffer[0];
    #else
        bool is_bsd = false;
        uint8_t buffer[2048];
        const int buffer_size = 2048;
    #endif
    
    timeout.tv_sec  = _timeout;
    end_time.tv_sec = static_cast<long>(time(0) + _timeout);
    end_time.tv_usec = timeout.tv_usec = timeout_usec_;
    while (true) {
        FD_ZERO(&readfds);
        int max_fd = 0;
        for (auto it = sockets.begin(); it != sockets.end(); ++it) {
            FD_SET(*it, &readfds);
            max_fd = (max_fd > *it) ? max_fd : *it;
        }
        if ((read = select(max_fd + 1, &readfds, 0, 0, &timeout)) == -1) {
            return 0;
        }
        if (read > 0) {
            for (auto it = sockets.begin(); it != sockets.end(); ++it) {
                if (FD_ISSET(*it, &readfds)) {
                    recvfrom_ret_type size;
                    // Crappy way of only conditionally running this on BSD + layer2
                    if (is_bsd && !is_layer_3) {
                        #if defined(BSD) || defined(__FreeBSD_kernel__)
                        size = ::read(*it, buffer, buffer_size_);
                        const uint8_t* ptr = buffer;
                        // We might see more than one packet
                        while (ptr < (buffer + size)) {
                            const bpf_hdr* bpf_header = reinterpret_cast<const bpf_hdr*>(ptr);
                            const uint8_t* pkt_start = ptr + bpf_header->bh_hdrlen;
                            if (pdu.matches_response(pkt_start, bpf_header->bh_caplen)) {
                                return Internals::pdu_from_flag(pdu.pdu_type(), pkt_start, bpf_header->bh_caplen);
                            }
                            ptr += BPF_WORDALIGN(bpf_header->bh_hdrlen + bpf_header->bh_caplen);
                        }
                        #endif // BSD
                    }
                    else {
                        socket_len_type length = addrlen;
                        size = ::recvfrom(*it, (char*)buffer, buffer_size, 0, link_addr, &length);
                        if (pdu.matches_response(buffer, size)) {
                            return Internals::pdu_from_flag(pdu.pdu_type(), buffer, size);
                        }
                    }
                }
            }
        }
        using namespace std::chrono;
        microseconds end = seconds(end_time.tv_sec) + microseconds(end_time.tv_usec);
        microseconds now = duration_cast<microseconds>(system_clock::now().time_since_epoch());
        if (now > end) {
            return 0;
        }
        // VC complains if we don't statically cast here
        #ifdef _WIN32
            typedef long tv_sec_type;
            typedef long tv_usec_type;
        #else
            using tv_sec_type = time_t;
            using tv_usec_type = long;
        #endif
        microseconds diff = end - now;
        timeout.tv_sec = static_cast<tv_sec_type>(duration_cast<seconds>(diff).count());
        timeout.tv_usec = static_cast<tv_usec_type>((diff - seconds(timeout.tv_sec)).count());
    }
    return 0;
}

int PacketSender::find_type(SocketType type) {
    auto it = types_.find(type);
    if (it == types_.end()) {
        return -1;
    }
    else {
        return it->second;
    }
}

} // Tins
