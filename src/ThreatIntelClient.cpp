#include "ThreatIntelClient.h"

#include <cstdlib>
#include <string>
#include <iostream>

#include <curl/curl.h>
#include <nlohmann/json.hpp>

namespace {
    std::size_t writeResponse(
        char* data,
        std::size_t size,
        std::size_t count,
        void* userData) {
        auto* response =
            static_cast<std::string*>(userData);

        response->append(data, size * count);

        return size * count;
    }
}

ThreatIntelClient::ThreatIntelClient() {
    const char* key =
        std::getenv("ABUSEIPDB_API_KEY");

    if (key != nullptr) {
        apiKey_ = key;
    }

    curlReady_ =
        curl_global_init(CURL_GLOBAL_DEFAULT)
        == CURLE_OK;
}

ThreatIntelClient::~ThreatIntelClient() {
    if (curlReady_) {
        curl_global_cleanup();
    }
}

bool ThreatIntelClient::isConfigured() const {
    return curlReady_ && !apiKey_.empty();
}

int ThreatIntelClient::getAbuseConfidenceScore(
    const std::string& ipAddress) const {
    if (!isConfigured()) {
        return -1;
    }

    CURL* curl = curl_easy_init();

    if (curl == nullptr) {
        return -1;
    }

    const std::string url =
        "https://api.abuseipdb.com/api/v2/check?ipAddress="
        + ipAddress
        + "&maxAgeInDays=90";

    const std::string keyHeader =
        "Key: " + apiKey_;

    std::string response;

    curl_slist* headers = nullptr;
    headers = curl_slist_append(
        headers, keyHeader.c_str());

    headers = curl_slist_append(
        headers, "Accept: application/json");

    curl_easy_setopt(
        curl, CURLOPT_URL, url.c_str());

    curl_easy_setopt(
        curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(
        curl, CURLOPT_WRITEFUNCTION,
        writeResponse);

    curl_easy_setopt(
        curl, CURLOPT_WRITEDATA, &response);

    curl_easy_setopt(
        curl, CURLOPT_TIMEOUT, 10L);

    const CURLcode result =
        curl_easy_perform(curl);

    long httpStatus = 0;

    curl_easy_getinfo(
        curl, CURLINFO_RESPONSE_CODE,
        &httpStatus);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK) {
        std::cerr << "AbuseIPDB request failed: "
                  << curl_easy_strerror(result) << '\n';

        return -1;
    }

    if (httpStatus != 200) {
        std::cerr << "AbuseIPDB returned HTTP status: "
                  << httpStatus << '\n';

        return -1;
    }


    try {
        const nlohmann::json report =
            nlohmann::json::parse(response);

        return report.at("data").value(
            "abuseConfidenceScore", -1);
    } catch (const nlohmann::json::exception& error) {
        std::cerr << "Could not parse AbuseIPDB response: "
                  << error.what() << '\n';

        return -1;
    }

}


