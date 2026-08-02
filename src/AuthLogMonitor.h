#pragma once

#include <fstream>
#include <string>
#include <vector>

class AuthLogMonitor {
    public:
    explicit AuthLogMonitor(
        const std::string& logPath);

    bool isReady() const;

    std::vector<std::string> readNewLines();

    private:
        std::ifstream logFile_;
};