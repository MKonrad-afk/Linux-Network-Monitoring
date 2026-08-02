cmake_minimum_required(VERSION 4.2)
project(Linux-Network-Monitoring)

set(CMAKE_CXX_STANDARD 20)

add_executable(Linux-Network-Monitoring src/main.cpp
        src/NetworkMonitor.cpp
        src/NetworkMonitor.h
        src/AlertLogger.cpp
        src/AlertLogger.h
        src/ThreatIntelClient.cpp
        src/ThreatIntelClient.h)

find_package(CURL    REQUIRED)
find_package(nlohmann_json REQUIRED)

target_link_libraries(Linux-Network-Monitoring PRIVATE
        CURL::libcurl
        nlohmann_json::nlohmann_json
)

