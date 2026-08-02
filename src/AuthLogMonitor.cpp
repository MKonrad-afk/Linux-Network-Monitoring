#include "AuthLogMonitor.h"

#include <ios>
#include <regex>

AuthLogMonitor::AuthLogMonitor(const std::string& logPath)
    : logFile_(logPath) {

    if (logFile_.is_open()) {
        logFile_.seekg(0, std::ios::end);
    }
}

bool AuthLogMonitor::isReady() const {
    return logFile_.is_open();
}

std::optional<AuthEvent> AuthLogMonitor::parseLine(
    const std::string& line) {

    static const std::regex sudoPattern(
        R"(sudo: ([^ ]+) : .* COMMAND=(.*))");

    static const std::regex failedSshPattern(
        R"(sshd.*Failed password for (?:invalid user )?([^ ]+) from ([^ ]+))");

    static const std::regex successfulSshPattern(
        R"(sshd.*Accepted \S+ for ([^ ]+) from ([^ ]+))");

    std::smatch match;

    if (std::regex_search(line, match, sudoPattern)) {
        return AuthEvent{
            AuthEventType::SudoCommand,
            match[1],
            "",
            match[2]
        };
    }

    if (std::regex_search(line, match, failedSshPattern)) {
        return AuthEvent{
            AuthEventType::FailedSshLogin,
            match[1],
            match[2],
            ""
        };
    }

    if (std::regex_search(line, match, successfulSshPattern)) {
        return AuthEvent{
            AuthEventType::SuccessfulSshLogin,
            match[1],
            match[2],
            ""
        };
    }

    return std::nullopt;
}

std::vector<AuthEvent> AuthLogMonitor::readNewEvents() {
    std::vector<AuthEvent> events;
    std::string line;

    logFile_.clear();

    while (std::getline(logFile_, line)) {
        const std::optional<AuthEvent> event = parseLine(line);

        if (event.has_value()) {
            events.push_back(event.value());
        }
    }

    return events;
}
std::size_t AuthLogMonitor::recordFailedLogin(
    const AuthEvent& event) {

    if (event.type != AuthEventType::FailedSshLogin ||
        event.sourceIp.empty()) {
        return 0;
        }

    const auto now = std::chrono::steady_clock::now();

    auto& attempts = failedLoginTimes_[event.sourceIp];

    while (!attempts.empty() &&
           now - attempts.front() > std::chrono::minutes(5)) {
        attempts.pop_front();
           }

    attempts.push_back(now);

    return attempts.size();
}




