#include "AuthLogMonitor.h"

#include <ios>

AuthLogMonitor::AuthLogMonitor(
    const std::string& logPath)
    : logFile_(logPath) {
    if (logFile_.is_open()) {
        logFile_.seekg(0, std::ios::end);
    }
}

bool AuthLogMonitor::isReady() const {
    return logFile_.is_open();
}

std::vector<std::string>
AuthLogMonitor::readNewLines() {
    std::vector<std::string> lines;
    std::string line;

    logFile_.clear();

    while (std::getline(logFile_, line)) {
        lines.push_back(line);
    }

    return lines;
}


