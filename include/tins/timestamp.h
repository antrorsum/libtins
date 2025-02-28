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

#ifndef TINS_TIMESTAMP_H
#define TINS_TIMESTAMP_H

#include <chrono>
#include <cstdint>
#include <tins/cxxstd.h>
#include <tins/macros.h>

struct timeval;

namespace Tins {

/**
 * \brief Represents a packet timestamp.
 */
class TINS_API Timestamp {
public:
    using seconds_type = time_t;
    using microseconds_type = suseconds_t;
    
    /**
     * \brief Constructs a Timestamp which will hold the current time.
     */
    static Timestamp current_time();
    
    /**
     * Default constructs a timestamp.
     */
    Timestamp();

    /**
     * Constructs a Timestamp from a std::chrono::duration.
     */
    template<typename Rep, typename Period>
    Timestamp(const std::chrono::duration<Rep, Period>& ts) {
        timestamp_ = std::chrono::duration_cast<std::chrono::microseconds>(ts).count();
    }
    
    /**
     * Constructs a timestamp from a timeval struct.
     *
     * \param time_val The timeval struct
     */
    Timestamp(const timeval& time_val);
    
    /**
     * Returns the amount of seconds in this timestamp.
     */
    seconds_type seconds() const;
    
    /**
     * \brief Returns the rest of the time in this timestamp in microseconds
     *
     * This is, after subtracting the seconds part, how many microseconds are 
     * left in this timestamp
     */
    microseconds_type microseconds() const;

    /**
     * Converts this Timestamp to a std::chrono::microseconds
     */
    operator std::chrono::microseconds() const {
        return std::chrono::microseconds(timestamp_);
    }
private:
    Timestamp(uint64_t value);

    uint64_t timestamp_{0};
};

} // Tins

#endif // TINS_TIMESTAMP_H
