#include "AlertSummarizer.h"


#include <curl/curl.h>
#include <nlohmann/json.hpp>

#include <iostream>
#include <string>
#include <utility>

namespace {
    std::size_t writeCallback(
        char* contents,
        std::size_t size,
        std::size_t count,
        void* userData) {

        const std::size_t totalSize = size * count;

        auto* response =
            static_cast<std::string*>(userData);

        response->append(contents, totalSize);

        return totalSize;
    }
}

AlertSummarizer::AlertSummarizer(
    std::string endpoint,
    std::string model)
    : endpoint_(std::move(endpoint)),
      model_(std::move(model)) {

    curl_global_init(CURL_GLOBAL_DEFAULT);
}

std::string AlertSummarizer::summarizeSshBruteForce(
    const std::string& sourceIp,
    const std::string& user,
    std::size_t failedAttempts) const {

    const std::string prompt =
        "You are assisting a security analyst. "
        "This event was detected by a deterministic rule, "
        "so do not claim it proves an attack. "
        "Return exactly two plain sentences, each no more than "
        "30 words. The first is an assessment; the second is "
        "a next investigation step. Do not use Markdown, headings, "
        "or bullet points.\n\n"
        "Event type: Possible SSH brute-force activity\n"
        "Source IP: " + sourceIp + "\n"
        "Target user: " + user + "\n"
        "Failed attempts within five minutes: " +
        std::to_string(failedAttempts);

    const nlohmann::json request = {
        {"model", model_},
        {"prompt", prompt},
        {"stream", false},
        {"options", {
            {"temperature", 0.2},
            {"num_predict", 110}
        }}
    };

    CURL* curl = curl_easy_init();

    if (curl == nullptr) {
        std::cerr << "Could not create Ollama request.\n";
        return "";
    }

    std::string responseBody;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(
        headers,
        "Content-Type: application/json");

    const std::string requestBody = request.dump();

    curl_easy_setopt(curl,CURLOPT_PROXY,"");
    curl_easy_setopt(curl, CURLOPT_URL, endpoint_.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDS,
        requestBody.c_str());

    curl_easy_setopt(
        curl,
        CURLOPT_POSTFIELDSIZE,
        static_cast<long>(requestBody.size()));

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEFUNCTION,
        writeCallback);

    curl_easy_setopt(
        curl,
        CURLOPT_WRITEDATA,
        &responseBody);

    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 3L);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);

    const CURLcode result = curl_easy_perform(curl);

    long httpStatus = 0;
    curl_easy_getinfo(
        curl,
        CURLINFO_RESPONSE_CODE,
        &httpStatus);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (result != CURLE_OK) {
        std::cerr << "Ollama request failed: "
                  << curl_easy_strerror(result)
                  << '\n';
        return "";
    }

    if (httpStatus != 200) {
        std::cerr << "Ollama returned HTTP status: "
                  << httpStatus
                  << '\n';
        return "";
    }

    try {
        const nlohmann::json response =
            nlohmann::json::parse(responseBody);

        return response.value("response", "");
    } catch (const std::exception& exception) {
        std::cerr << "Could not parse Ollama response: "
                  << exception.what()
                  << '\n';
        return "";
    }
}


