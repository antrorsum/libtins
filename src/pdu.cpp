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
 
#include <tins/pdu.h>
#include <tins/packet_sender.h>

using std::swap;
using std::vector;

namespace Tins {

PDU::metadata::metadata()  = default;
        
PDU::metadata::metadata(uint32_t header_size, PDUType current_type, PDUType next_type) 
: header_size(header_size), current_pdu_type(current_type), next_pdu_type(next_type) {

}

// PDU

PDU::PDU() = default;

PDU::PDU(const PDU& other) 
: inner_pdu_(), parent_pdu_() {
    copy_inner_pdu(other);
}

PDU& PDU::operator=(const PDU& other) {
    copy_inner_pdu(other);
    return* this;
}

PDU::~PDU() {
    delete inner_pdu_;
}

void PDU::copy_inner_pdu(const PDU& pdu) {
    if (pdu.inner_pdu()) {
        inner_pdu(pdu.inner_pdu()->clone());
    }
}

void PDU::prepare_for_serialize() {
}

uint32_t PDU::size() const {
    uint32_t sz = header_size() + trailer_size();
    const PDU* ptr(inner_pdu_);
    while (ptr) {
        sz += ptr->header_size() + ptr->trailer_size();
        ptr = ptr->inner_pdu();
    }
    return sz;
}

uint32_t PDU::advertised_size() const {
    uint32_t result = header_size() + trailer_size();
    if (inner_pdu_) {
        result += inner_pdu()->advertised_size();
    }
    return result;
}

void PDU::send(PacketSender &, const NetworkInterface &) { 
    
}

PDU* PDU::recv_response(PacketSender &, const NetworkInterface &) { 
    return nullptr; 
}

bool PDU::matches_response(const uint8_t* /*ptr*/, uint32_t /*total_sz*/) const {
    return false;
}

void PDU::inner_pdu(PDU* next_pdu) {
    delete inner_pdu_;
    inner_pdu_ = next_pdu;
    if (inner_pdu_) {
        inner_pdu_->parent_pdu(this);
    }
}

void PDU::inner_pdu(const PDU& next_pdu) {
    inner_pdu(next_pdu.clone());
}

PDU* PDU::release_inner_pdu() {
    PDU* result = nullptr;
    swap(result, inner_pdu_);
    if (result) {
        result->parent_pdu(nullptr);
    }
    return result;
}

PDU::serialization_type PDU::serialize() {
    vector<uint8_t> buffer(size());
    serialize(&buffer[0], static_cast<uint32_t>(buffer.size()));
    return buffer;
}

void PDU::serialize(uint8_t* buffer, uint32_t total_sz) {
    uint32_t sz = header_size() + trailer_size();
    // Must not happen...
    #ifdef TINS_DEBUG
    assert(total_sz >= sz);
    #endif
    prepare_for_serialize();
    if (inner_pdu_) {
        inner_pdu_->serialize(buffer + header_size(), total_sz - sz);
    }
    write_serialization(buffer, total_sz);
}

void PDU::parent_pdu(PDU* parent) {
    parent_pdu_ = parent;
}

} // Tins
