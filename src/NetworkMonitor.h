#pragma once

#include <map>
#include <string>

class NetworkMonitor {
public:
    std::map<std::string, std::string> getConnections() const;

private:
    static std::string normalizeEndpoint(
        const std::string& endpoint);

    static bool isLoopbackEndpoint(
        const std::string& endpoint);

    static std::string trim(
        const std::string& text);
};


