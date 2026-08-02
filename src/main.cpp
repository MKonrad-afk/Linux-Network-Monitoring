#include "AlertLogger.h"
#include "NetworkMonitor.h"
#include "ThreatIntelClient.h"

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

int main() {
    NetworkMonitor monitor;
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

    while (true) {
        std::this_thread::sleep_for(
            std::chrono::seconds(5));

        const std::map<std::string, std::string>
            currentConnections =
                monitor.getConnections();

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


