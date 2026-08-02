#pragma once

#include <string>

class AlertLogger {
public:
    explicit AlertLogger(std::string logPath);

    void alert(const std::string& endpoint,
               const std::string& processInfo,
               const std::string& severity,
               int abuseScore) const;

    void trustedEndpoint(
        const std::string& endpoint) const;

private:
    std::string logPath_;

    static std::string currentTimestamp();

    static std::string formatProcessInfo(
        const std::string& processInfo);
};


