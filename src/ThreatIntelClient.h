#pragma once

#include <string>

class ThreatIntelClient {
    public:
    ThreatIntelClient();
    ~ThreatIntelClient();

    bool isConfigured() const;

    int getAbuseConfidenceScore(const std::string& ipAddress) const;

    private:
    std::string apiKey_;
    bool curlReady_ =false;
};