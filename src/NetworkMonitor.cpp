#include "NetworkMonitor.h"

#include <cstdio>
#include <sstream>

std::string NetworkMonitor::normalizeEndpoint(
    const std::string& endpoint) {
    const std::string prefix = "[::ffff:";

    if (endpoint.rfind(prefix, 0) != 0) {
        return endpoint;
    }

    const std::size_t closingBracket =
        endpoint.find("]:");

    if (closingBracket == std::string::npos) {
        return endpoint;
    }

    return endpoint.substr(
               prefix.size(),
               closingBracket - prefix.size())
           + endpoint.substr(closingBracket + 1);
}

bool NetworkMonitor::isLoopbackEndpoint(
    const std::string& endpoint) {
    return endpoint.rfind("127.", 0) == 0 ||
           endpoint.rfind("[::1]:", 0) == 0;
}

std::string NetworkMonitor::trim(
    const std::string& text) {
    const std::size_t firstCharacter =
        text.find_first_not_of(" \t\r\n");

    if (firstCharacter == std::string::npos) {
        return "";
    }

    return text.substr(firstCharacter);
}

std::map<std::string, std::string>
NetworkMonitor::getConnections() const {
    const char* command =
        "ss -H -tunpO state established";

    FILE* pipe = popen(command, "r");

    if (pipe == nullptr) {
        return {};
    }

    std::map<std::string, std::string> connections;
    char buffer[512];

    while (fgets(buffer, sizeof(buffer), pipe)
           != nullptr) {
        std::istringstream line(buffer);

        std::string protocol;
        std::string receiveQueue;
        std::string sendQueue;
        std::string localAddress;
        std::string remoteAddress;

        if (line >> protocol >> receiveQueue
                 >> sendQueue >> localAddress
                 >> remoteAddress) {
            std::string processInfo;

            std::getline(line, processInfo);

            remoteAddress =
                normalizeEndpoint(remoteAddress);

            processInfo = trim(processInfo);

            if (processInfo.empty()) {
                processInfo =
                    "unavailable (permission restricted "
                    "or kernel socket)";
            }

            if (!isLoopbackEndpoint(remoteAddress)) {
                connections[remoteAddress] = processInfo;
            }
        }
    }

    pclose(pipe);

    return connections;
}


