FIND_PACKAGE(Threads QUIET)
FIND_PACKAGE(Boost COMPONENTS regex)

SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/examples)
INCLUDE_DIRECTORIES(
    ${PROJECT_SOURCE_DIR}/include
    ${PCAP_INCLUDE_DIR}
)
LINK_LIBRARIES(tins)

SET(LIBTINS_CXX11_EXAMPLES
    arpmonitor
    dns_queries
    dns_spoof
    dns_stats
    stream_dump
    icmp_responses
    interfaces_info
    tcp_connection_close
    traceroute
    wps_detect
)
IF(Boost_REGEX_FOUND)
    SET(LIBTINS_CXX11_EXAMPLES ${LIBTINS_CXX11_EXAMPLES} http_requests)
ELSE()
    MESSAGE(WARNING "Disabling HTTP requests example since boost.regex was not found")
ENDIF()

ADD_CUSTOM_TARGET(
    examples DEPENDS
    arpspoofing
    ${LIBTINS_CXX11_EXAMPLES}
    beacon_display
    portscan
    route_table
    defragmenter
)

# Make sure we first build libtins
ADD_DEPENDENCIES(examples tins)

ADD_EXECUTABLE(arpspoofing EXCLUDE_FROM_ALL arpspoofing.cpp)
ADD_EXECUTABLE(route_table EXCLUDE_FROM_ALL route_table.cpp)
ADD_EXECUTABLE(defragmenter EXCLUDE_FROM_ALL defragmenter.cpp)
ADD_EXECUTABLE(arpmonitor EXCLUDE_FROM_ALL arpmonitor.cpp)
ADD_EXECUTABLE(dns_queries EXCLUDE_FROM_ALL dns_queries.cpp)
ADD_EXECUTABLE(dns_spoof EXCLUDE_FROM_ALL dns_spoof.cpp)
ADD_EXECUTABLE(stream_dump EXCLUDE_FROM_ALL stream_dump.cpp)
ADD_EXECUTABLE(icmp_responses EXCLUDE_FROM_ALL icmp_responses.cpp)
ADD_EXECUTABLE(interfaces_info EXCLUDE_FROM_ALL interfaces_info.cpp)
ADD_EXECUTABLE(tcp_connection_close EXCLUDE_FROM_ALL tcp_connection_close.cpp)
ADD_EXECUTABLE(wps_detect EXCLUDE_FROM_ALL wps_detect.cpp)
IF (Boost_REGEX_FOUND)
    ADD_EXECUTABLE(http_requests EXCLUDE_FROM_ALL http_requests.cpp)
    TARGET_LINK_LIBRARIES(http_requests ${Boost_LIBRARIES})
ENDIF()

ADD_EXECUTABLE(beacon_display EXCLUDE_FROM_ALL beacon_display.cpp)

if(THREADS_FOUND)
    ADD_EXECUTABLE(traceroute EXCLUDE_FROM_ALL traceroute.cpp)
    ADD_EXECUTABLE(dns_stats EXCLUDE_FROM_ALL dns_stats.cpp)
    TARGET_LINK_LIBRARIES(traceroute ${CMAKE_THREAD_LIBS_INIT})
    TARGET_LINK_LIBRARIES(dns_stats ${CMAKE_THREAD_LIBS_INIT})
    ADD_EXECUTABLE(portscan EXCLUDE_FROM_ALL portscan.cpp)
    TARGET_LINK_LIBRARIES(portscan ${CMAKE_THREAD_LIBS_INIT})
ELSE()
    MESSAGE(WARNING "Disabling portscan and traceroute examples since pthreads library was not found.")
ENDIF()
