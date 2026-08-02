#include <iostream>
#include <vector>
#include <string>
#include <sstream>
#include <set>
#include <chrono>
#include <thread>

using std::cout;
using std::cerr;
using std::vector;
using std::string;
using std::set;

bool isLoopbackEndpoint(const string& endpoint) {
    return endpoint.rfind("127.", 0) == 0 ||
            endpoint.rfind("::1", 0) == 0 ||
            endpoint.rfind("::ffff:127", 0) == 0;
}
set<string> getRemoteEndpoints() {
    const char* command = "ss -H -tun state established";
    FILE* pipe = popen(command, "r");

    if (pipe == nullptr) {
        cerr << "Could not run ss.\n ";
        return {};
    }
    set<string> endpoints;
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
            if (!isLoopbackEndpoint(remoteAddress)) {
                endpoints.insert(remoteAddress);
            }
        }
    }
    pclose(pipe);
    return endpoints;
};
int main(){
    cout << "SentinelLite started.\n";
    set<string>  knownEndpoints = getRemoteEndpoints();

    cout << "Monitoring started.\n";
    cout<< "Known endpoint(s): [" << knownEndpoints.size() << "].\n";
    cout << "Checking every 5 seconds...\n Stop with Ctrl+C\n";

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(5));
        const set<string> current = getRemoteEndpoints();

        for (const string& endpoint: current) {
            if (knownEndpoints.find(endpoint)== knownEndpoints.end()) {
                cout << "[ALERT] New remote endpoint: " << endpoint << "\n";

                knownEndpoints.insert(endpoint);
            }
        }


    }
    return 0;
}