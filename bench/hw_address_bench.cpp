#include <benchmark/benchmark.h>
#include <algorithm>
#include <string>
#include <map>
#include <sstream>
#include <stdint.h>
#include <tins/hw_address.h>

static void BM_isMulticast(benchmark::State& state) {
  // Perform setup here
  for (auto _ : state) {
    Tins::HWAddress<6>("01:02:03:04:05:06").is_multicast();
  }
}

static void BM_isBroadcast(benchmark::State& state) {
  // Perform setup here
  for (auto _ : state) {
    Tins::HWAddress<6>("ff:ff:ff:ff:ff:ff").is_broadcast();
  }
}

static void BM_isUnicast(benchmark::State& state) {
  // Perform setup here
  for (auto _ : state) {
    Tins::HWAddress<6>("de:ad:be:ef:00:00").is_unicast();
  }
}

// Register the function as a benchmark
BENCHMARK(BM_isMulticast);
BENCHMARK(BM_isBroadcast);
BENCHMARK(BM_isUnicast);
