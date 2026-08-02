#pragma once

#include <string>

class ThreatIntelClient {
    public:
    ThreatIntelClient();
    bool isConfigured() const;

    private:
    std::string apiKey_;
};