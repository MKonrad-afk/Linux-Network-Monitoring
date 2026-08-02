#pragma once

#include <fstream>
#include <optional>
#include <string>
#include <vector>
#include <chrono>
#include <deque>
#include <map>

enum class AuthEventType {
    SudoCommand,
    FailedSshLogin,
    SuccessfulSshLogin
};

struct AuthEvent {
    AuthEventType type;
    std::string user;
    std::string sourceIp;
    std::string details;
};

class AuthLogMonitor {
public:
    explicit AuthLogMonitor(const std::string& logPath);

    bool isReady() const;

    std::vector<AuthEvent> readNewEvents();
    
    static constexpr std::size_t bruteForceThreshold = 5;

    std::size_t recordFailedLogin(const AuthEvent& event);

private:
    std::ifstream logFile_;

    static std::optional<AuthEvent> parseLine(
        const std::string& line);

    std::map<std::string, std::deque<std::chrono::steady_clock::time_point>> failedLoginTimes_;
};


