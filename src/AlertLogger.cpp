#include "AlertLogger.h"

#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <nlohmann/json.hpp>

AlertLogger::AlertLogger(std::string logPath)
    : logPath_(std::move(logPath)) {
}

std::string AlertLogger::currentTimestamp() {
    const std::time_t now = std::time(nullptr);
    const std::tm* localTime = std::localtime(&now);

    if (localTime == nullptr) {
        return "unknown-time";
    }

    std::ostringstream timestamp;

    timestamp << std::put_time(
        localTime, "%Y-%m-%d %H:%M:%S");

    return timestamp.str();
}

std::string AlertLogger::formatProcessInfo(
    const std::string& processInfo) {
    const std::size_t nameStart =
        processInfo.find('"');

    if (nameStart == std::string::npos) {
        return processInfo;
    }

    const std::size_t nameEnd =
        processInfo.find('"', nameStart + 1);

    const std::size_t pidStart =
        processInfo.find("pid=");

    if (nameEnd == std::string::npos ||
        pidStart == std::string::npos) {
        return processInfo;
    }

    const std::size_t pidEnd =
        processInfo.find(',', pidStart);

    if (pidEnd == std::string::npos) {
        return processInfo;
    }

    const std::string processName =
        processInfo.substr(
            nameStart + 1,
            nameEnd - nameStart - 1);

    const std::string processId =
        processInfo.substr(
            pidStart + 4,
            pidEnd - pidStart - 4);

    return processName + " (PID " + processId + ")";
}

void AlertLogger::alert(
    const std::string& endpoint,
    const std::string& processInfo,
    const std::string& severity,
    int abuseScore) const {
    const std::string timestamp = currentTimestamp();
    const std::string processSummary =
        formatProcessInfo(processInfo);

    std::cout << "[" << severity << "]["
              << timestamp
              << "] New remote endpoint: "
              << endpoint << '\n';

    std::cout << "              Process: "
              << processSummary << '\n';

    if (abuseScore >= 0) {
        std::cout << "              AbuseIPDB score: "<< abuseScore << "%\n";
    } else {
        std::cout<< "              AbuseIPDB score: unavailable\n";
    }




    std::ofstream alertLog(logPath_, std::ios::app);

    if (!alertLog) {
        std::cerr << "Could not open alert log.\n";
        return;
    }

    nlohmann::json alert = {
        {"timestamp", timestamp},
        {"severity", severity},
        {"rule", "new_outbound_connection"},
        {"endpoint", endpoint},
        {"process", processSummary}
    };

    if (abuseScore >= 0) {
        alert["abuseipdb_score"] = abuseScore;
    } else {
        alert["abuseipdb_score"] = nullptr;
    }

    alertLog << alert.dump() << '\n';

}

void AlertLogger::trustedEndpoint(
    const std::string& endpoint) const {
    std::cout << "[INFO] Trusted endpoint seen: "
              << endpoint << '\n';
}


