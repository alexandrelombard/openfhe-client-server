#include <iostream>

#include <openfhe.h>
#include <httpserver.hpp>

using namespace lbcrypto;
using namespace std;

class hello_world_resource : public httpserver::http_resource {
public:
    std::shared_ptr<httpserver::http_response> render(const httpserver::http_request&) {
        return std::shared_ptr<httpserver::http_response>(new httpserver::string_response("Hello, World!"));
    }
};

int main(int argc, char* argv[]) {
    httpserver::webserver ws = httpserver::create_webserver(8080);

    hello_world_resource hwr;
    ws.register_resource("/hello", &hwr);
    ws.start(true);

    return EXIT_SUCCESS;
}