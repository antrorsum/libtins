set(SOURCES
    "main"
    "hw_address_bench"
    "address_range_bench")

INCLUDE_DIRECTORIES(
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

add_executable("${PROJECT_NAME}-bench" ${SOURCES})
set_target_properties("${PROJECT_NAME}-bench" PROPERTIES CXX_STANDARD 17)
target_link_libraries("${PROJECT_NAME}-bench" benchmark tins)