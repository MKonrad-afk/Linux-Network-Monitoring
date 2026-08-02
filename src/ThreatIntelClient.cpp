#include "ThreatIntelClient.h"

#include <cstdlib>

ThreatIntelClient::ThreatIntelClient() {
    const char* key =
        std::getenv("ABUSEIPDB_API_KEY");

    if (key != nullptr) {
        apiKey_ = key;
    }
}

bool ThreatIntelClient::isConfigured() const {
    return !apiKey_.empty();
}


