#pragma once

#include <string>
#include <map>

class ThreatIntelClient {
    public:
    ThreatIntelClient();
    ~ThreatIntelClient();

    bool isConfigured() const;

    int getAbuseConfidenceScore(const std::string& ipAddress);

    private:
    std::string apiKey_;
    bool curlReady_ =false;
    std::map<std::string, int> scoreCache_;
};