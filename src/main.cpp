#include "AlertLogger.h"
#include "NetworkMonitor.h"
#include "ThreatIntelClient.h"
#include "AuthLogMonitor.h"

#include <chrono>
#include <fstream>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <thread>

std::set<std::string> loadTrustedEndpoints(
    const std::string& path) {
    std::ifstream trustedFile(path);
    std::set<std::string> endpoints;
    std::string endpoint;

    while (std::getline(trustedFile, endpoint)) {
        if (!endpoint.empty() && endpoint[0] != '#') {
            endpoints.insert(endpoint);
        }
    }

    return endpoints;
}

int main(int argc, char* argv[]) {
    NetworkMonitor monitor;
    AuthLogMonitor authMonitor("/var/log/auth.log");

    const bool demoBruteForce =  argc > 1  && std::string(argv[1]) == "--demo-bruteforce";

    if (authMonitor.isReady()) {
        std::cout << "Authentication log monitoring enabled.\n";
    } else {
        std::cout << "Authentication log monitoring unavailable.\n";
    }

    AlertLogger logger("alerts.jsonl");
    ThreatIntelClient threatIntel;

    if (threatIntel.isConfigured()) {
        std::cout << "AbuseIPDB key detected.\n";

    }
    else {
        std::cout << "AbuseIPDB key not configured.\n";
    }

    const std::set<std::string> trustedEndpoints =
        loadTrustedEndpoints("trusted_endpoints.txt");

    std::map<std::string, std::string> knownEndpoints =
        monitor.getConnections();

    std::cout
        << "Linux Network Monitoring started (SentinelLIte).\n";

    std::cout << "Trusted endpoints: ["
              << trustedEndpoints.size() <<"]"<< '\n';

    std::cout << "Known endpoints: ["
              << knownEndpoints.size() <<"]"<< '\n';

    std::cout
        << "Checking every 5 seconds. Stop with Ctrl+C.\n";


    if (demoBruteForce) {
        std::cout << "Running safe SSH brute-force detection demo.\n";

        const AuthEvent demoEvent{
            AuthEventType::FailedSshLogin,
            "demo-user",
            "203.0.113.10",
            ""
        };

        for (std::size_t i = 0;
             i < AuthLogMonitor::bruteForceThreshold;
             ++i) {

            const std::size_t attempts =
                authMonitor.recordFailedLogin(demoEvent);

            std::cout << "[AUTH][MEDIUM] Failed SSH login for "
                      << demoEvent.user
                      << " from "
                      << demoEvent.sourceIp
                      << " (" << attempts
                      << " recent attempt(s))\n";

            if (attempts == AuthLogMonitor::bruteForceThreshold) {
                std::cout
                    << "[AUTH][HIGH] Possible SSH brute-force attack "
                    << "from " << demoEvent.sourceIp
                    << ": " << attempts
                    << " failed logins within 5 minutes.\n";
            }
             }

        return 0;
    }

    while (true) {
        std::this_thread::sleep_for(
            std::chrono::seconds(5));

        const std::map<std::string, std::string>
            currentConnections =
                monitor.getConnections();

        for (const AuthEvent& event : authMonitor.readNewEvents()) {
            switch (event.type) {
                case AuthEventType::SudoCommand:
                    std::cout << "[AUTH][INFO] Sudo command by "
                              << event.user
                              << ": "
                              << event.details
                              << '\n';
                    break;
                case AuthEventType::FailedSshLogin: {
                    const std::size_t attempts =
                        authMonitor.recordFailedLogin(event);

                    std::cout << "[AUTH][MEDIUM] Failed SSH login for "
                              << event.user
                              << " from "
                              << event.sourceIp
                              << " (" << attempts << " recent attempt(s))"
                              << '\n';

                    if (attempts == AuthLogMonitor::bruteForceThreshold) {
                        std::cout << "[AUTH][HIGH] Possible SSH brute-force attack "
                                  << "from " << event.sourceIp
                                  << ": " << attempts
                                  << " failed logins within 5 minutes.\n";
                    }

                    break;
                }
                case AuthEventType::SuccessfulSshLogin:
                    std::cout << "[AUTH][INFO] Successful SSH login for "
                              << event.user
                              << " from "
                              << event.sourceIp
                              << '\n';
                    break;
            }
        }
        for (const auto& [endpoint, processInfo]
             : currentConnections) {
            if (knownEndpoints.find(endpoint)
                != knownEndpoints.end()) {
                continue;
                }

            if (trustedEndpoints.find(endpoint)
                != trustedEndpoints.end()) {
                logger.trustedEndpoint(endpoint);
                } else {
                    const std::size_t portSeparator =
                    endpoint.rfind(':');

                    const std::string ipAddress =endpoint.substr(0, portSeparator);

                    const int abuseScore =threatIntel.getAbuseConfidenceScore(ipAddress);

                    const std::string severity =
                        abuseScore >= 50 ? "HIGH" : "MEDIUM";

                    logger.alert(
                        endpoint,
                        processInfo,
                        severity,
                        abuseScore);
                }
            knownEndpoints[endpoint] = processInfo;
             }
    }
}


