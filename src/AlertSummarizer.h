#pragma once

#include <cstddef>
#include <string>

class AlertSummarizer {
public:
    AlertSummarizer(std::string endpoint,
                    std::string model);

    std::string summarizeSshBruteForce(
        const std::string& sourceIp,
        const std::string& user,
        std::size_t failedAttempts) const;

private:
    std::string endpoint_;
    std::string model_;
};


