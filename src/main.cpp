#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <map>
#include <fstream>
#include <ctime>
#include  <iomanip>
#include <set>

using std::cout;
using std::cerr;
using std::vector;
using std::string;
using std::map;
using std::ios;
using std::ofstream;
using std::ifstream;
using std::set;

string normalizeEndpoint(const string& endpoint) {
    const string prefix = "[::ffff:";

    if (endpoint.rfind(prefix, 0) != 0) {
        return endpoint;
    }
    const size_t closingBracket = endpoint.rfind(']');

    if (closingBracket != string::npos) {
        return endpoint;
    }
    return endpoint.substr(prefix.size(),
        closingBracket - prefix.size())+ endpoint.substr( closingBracket+1);
}

bool isLoopbackEndpoint(const string& endpoint) {
    return endpoint.rfind("127.", 0) == 0 ||
            endpoint.rfind("::1", 0) == 0 ||
            endpoint.rfind("::ffff:127", 0) == 0;
}
map<string,string> getRemoteEndpoints() {
    const char* command = "ss -H -tunp0 state established";
    FILE* pipe = popen(command, "r");

    if (pipe == nullptr) {
        cerr << "Could not run ss.\n ";
        return {};
    }
    map<string,string> endpoints;
    char buffer[512];

    while (fgets(buffer,sizeof(buffer),pipe) != nullptr) {
        std::istringstream line(buffer);

        string protocol;
        string state;
        string receiveQueue;
        string sendQueue;
        string localAddress;
        string remoteAddress;

        if ( line >> protocol >> state >> receiveQueue >> localAddress >> remoteAddress ) {
            string processInfo;
            std::getline(line,processInfo);
            remoteAddress = normalizeEndpoint(remoteAddress);
            if (processInfo.empty()) {
                processInfo = "unavailable (permission restricted or kernel socket";
            }
            if (!isLoopbackEndpoint(remoteAddress)) {
                endpoints[remoteAddress] = processInfo;
            }
        }
    }
    pclose(pipe);
    return endpoints;
};
string currentTimeStamp() {
    const std::time_t now = std::time(nullptr);
    const std::tm* localTime = std::localtime(&now);

    if (localTime == nullptr) {
        return "unknown-time-stamp";
    }
    std::ostringstream timestamp;
    timestamp << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");
    return timestamp.str();
}

void saveAlert(const string& timestamp, const string& endpoint, const string& processInfo) {
    ofstream alertLog("alerts.log",ios::app);
    if (!alertLog) {
        cerr << "Could not open alert log file.\n ";
        return;
    }
    alertLog << "[ALERT]["<<timestamp<<"] New remote endpoint: " << endpoint << "\n";
    alertLog << "              Process: " << processInfo << "\n";
}

set<string> loadTrustedEndpoints() {
    ifstream trustedFile("trusted_endpoints.txt");
    set<string> trustedEndpoints;
    string endpoint;
    while (std::getline(trustedFile,endpoint)) {
        if (!endpoint.empty() && endpoint[0]!='#') {
            trustedEndpoints.insert(endpoint);
        }
    }
    return trustedEndpoints;
}
int main(){
    cout << "SentinelLite started.\n";

    const set<string> trustedEndpoints = loadTrustedEndpoints();
    cout<< "Trusted endpoint(s): [" << trustedEndpoints.size() << "].\n";

    map<string,string>  knownEndpoints = getRemoteEndpoints();

    cout << "Monitoring started.\n";
    cout<< "Known endpoint(s): [" << knownEndpoints.size() << "].\n";
    cout << "Checking every 5 seconds...\n Stop with Ctrl+C\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        const map<string,string> current = getRemoteEndpoints();

        for (const auto& [endpoint,processInfo]: current) {
            if (trustedEndpoints.find(endpoint)== trustedEndpoints.end()) {
                cout << "[INFO] Trusted endpoint seen: " << endpoint << "\n";
            }
            else{
                const string timestamp = currentTimeStamp();
                cout << "[ALERT]["<<timestamp<<"] New remote endpoint: " << endpoint << "\n";
                cout << "              Process: " << processInfo << "\n";
                saveAlert(timestamp , endpoint, processInfo);

            }
            knownEndpoints[endpoint] = processInfo;
        }


    }
    return 0;
}