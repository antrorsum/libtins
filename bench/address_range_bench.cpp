#include <benchmark/benchmark.h>
#include <algorithm>
#include <string>
#include <map>
#include <sstream>
#include <stdint.h>
#include <tins/address_range.h>
#include <tins/ip_address.h>
#include <tins/ipv6_address.h>

static void BM_IPv4AddrRange(benchmark::State& state) {
  // Perform setup here
  for (auto _ : state) {
    Tins::IPv4Range::from_mask("192.168.0.0", "255.255.255.0");
  }
}

// Register the function as a benchmark
BENCHMARK(BM_IPv4AddrRange);
