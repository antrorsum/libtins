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
#include <tins/exceptions.h>
#include <tins/offline_packet_filter.h>
#include <tins/pdu.h>

using std::string;

namespace Tins {

OfflinePacketFilter::OfflinePacketFilter(const OfflinePacketFilter& other) {
    string_filter_ = other.string_filter_;
    init(string_filter_, pcap_datalink(other.handle_), pcap_snapshot(other.handle_));
}

OfflinePacketFilter& OfflinePacketFilter::operator=(const OfflinePacketFilter& other) {
    string_filter_ = other.string_filter_;
    pcap_freecode(&filter_);
    pcap_close(handle_);
    init(string_filter_, pcap_datalink(other.handle_), pcap_snapshot(other.handle_));
    return* this;
}

OfflinePacketFilter::~OfflinePacketFilter() {
    pcap_freecode(&filter_);
    pcap_close(handle_);
}

void OfflinePacketFilter::init(const string& pcap_filter, 
                               int link_type, 
                               unsigned int snap_len) {
    handle_ = pcap_open_dead(
        link_type,
        snap_len
    );
    if (!handle_) {
        throw pcap_open_failed();
    }
    if (pcap_compile(handle_, &filter_, pcap_filter.c_str(), 1, 0xffffffff) == -1) {
        string error(pcap_geterr(handle_));
        pcap_freecode(&filter_);
        pcap_close(handle_);
        throw invalid_pcap_filter(error.c_str());
    }
}

bool OfflinePacketFilter::matches_filter(const uint8_t* buffer, uint32_t total_sz) const {
    pcap_pkthdr header;
    memset(&header, 0, sizeof(header));
    header.len = total_sz;
    header.caplen = total_sz;
    return pcap_offline_filter(&filter_, &header, buffer) != 0;
}

bool OfflinePacketFilter::matches_filter(PDU& pdu) const {
    PDU::serialization_type buffer = pdu.serialize();
    return matches_filter(&buffer[0], static_cast<uint32_t>(buffer.size()));
}

} // Tins
