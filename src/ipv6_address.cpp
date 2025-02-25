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

#include <tins/macros.h>
#include <arpa/inet.h>
// std::hash
#include <memory>
#include <limits>
#include <sstream>
#include <iostream>
#include <tins/ipv6_address.h>
#include <tins/address_range.h>
#include <tins/exceptions.h>

using std::memset;
using std::memcpy;
using std::string;
using std::ostream;

namespace Tins {

const IPv6Address loopback_address = "::1";
const AddressRange<IPv6Address> multicast_range = IPv6Address("ff00::") / 8;
const AddressRange<IPv6Address> local_unicast_range = IPv6Address("fe80::") / 10;

IPv6Address IPv6Address::from_prefix_length(uint32_t prefix_length) {
    IPv6Address address;
    IPv6Address::iterator it = address.begin();
    while (prefix_length > 8) {
        *it = 0xff;
        ++it;
        prefix_length -= 8;
    }
    *it = 0xff << (8 - prefix_length);
    return address;
}

IPv6Address::IPv6Address() {
    memset(address_, 0, address_size);
}

IPv6Address::IPv6Address(const char* addr) {
    init(addr);
}

IPv6Address::IPv6Address(const_iterator ptr) {
    memcpy(address_, ptr, address_size);
}

IPv6Address::IPv6Address(const std::string& addr) {
    init(addr.c_str());
}

void IPv6Address::init(const char* addr) {
    if (inet_pton(AF_INET6, addr, address_) == 0) {
        throw invalid_address();
    }          
}

string IPv6Address::to_string() const {
    char buffer[INET6_ADDRSTRLEN];
    if (inet_ntop(AF_INET6, address_, buffer, sizeof(buffer)) == nullptr) {
        throw invalid_address();
    }
    return buffer;
}

bool IPv6Address::is_loopback() const {
    return loopback_address == *this;
}

bool IPv6Address::is_multicast() const {
    return multicast_range.contains(*this);
}

bool IPv6Address::is_local_unicast() const {
    return local_unicast_range.contains(*this);
}

ostream& operator<<(ostream& os, const IPv6Address& addr) {
    return os << addr.to_string();
}

IPv6Address IPv6Address::operator&(const IPv6Address& rhs) const {
    IPv6Address result = *this;
    IPv6Address::iterator addr_iter = result.begin();
    for (IPv6Address::const_iterator it = rhs.begin(); it != rhs.end(); ++it, ++addr_iter) {
        *addr_iter = *addr_iter & *it;
    }

    return result;
}

IPv6Address IPv6Address::operator|(const IPv6Address& rhs) const {
     IPv6Address result = *this;
    IPv6Address::iterator addr_iter = result.begin();
    for (IPv6Address::const_iterator it = rhs.begin(); it != rhs.end(); ++it, ++addr_iter) {
        *addr_iter = *addr_iter | *it;
    }

    return result;
}

IPv6Address IPv6Address::operator~() const {
    IPv6Address result  = *this;
    for (unsigned char & addr_iter : result) {
        addr_iter = ~addr_iter;
    }

   return result;
}

} // Tins
