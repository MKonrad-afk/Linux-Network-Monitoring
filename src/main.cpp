#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <chrono>
#include <thread>
#include <map>

using std::cout;
using std::cerr;
using std::vector;
using std::string;
using std::map;

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
int main(){
    cout << "SentinelLite started.\n";
    map<string,string>  knownEndpoints = getRemoteEndpoints();

    cout << "Monitoring started.\n";
    cout<< "Known endpoint(s): [" << knownEndpoints.size() << "].\n";
    cout << "Checking every 5 seconds...\n Stop with Ctrl+C\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        const map<string,string> current = getRemoteEndpoints();

        for (const auto& [endpoint,processInfo]: current) {
            if (knownEndpoints.find(endpoint)== knownEndpoints.end()) {
                cout << "[ALERT] New remote endpoint: " << endpoint << "\n";
                cout << "              Process: " << processInfo << "\n";

                knownEndpoints[endpoint] = processInfo;
            }
        }


    }
    return 0;
}