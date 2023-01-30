#include <iostream>

#include <openfhe.h>
#include <httpserver.hpp>

// header files needed for serialization
#include <ciphertext-ser.h>
#include <cryptocontext-ser.h>
//#include <key/key-ser.h>
//#include <scheme/ckksrns/ckksrns-ser.h>

using namespace lbcrypto;
using namespace std;

class hello_world_resource : public httpserver::http_resource {
public:
    std::shared_ptr<httpserver::http_response> render(const httpserver::http_request&) {
        return std::shared_ptr<httpserver::http_response>(new httpserver::string_response("Hello, World!"));
    }
};

class crypto_context_resource : public httpserver::http_resource {
private:
    CryptoContext<DCRTPoly>& cryptoContext;
public:
    explicit crypto_context_resource(CryptoContext<DCRTPoly>& cryptoContext) : cryptoContext(cryptoContext) {}

    std::shared_ptr<httpserver::http_response> render(const httpserver::http_request&) {
        // Serialize Crypto Context
        std::cout << "GET /crypto_context" << std::endl;
        try {
            if(!Serial::SerializeToFile("cryptocontext.txt", this->cryptoContext, SerType::BINARY)) {
                std::cerr << "Error writing serialization of the crypto context" << std::endl;
            }
            std::string serializedContext = Serial::SerializeToString(this->cryptoContext);
            std::cout << serializedContext << std::endl;
            return std::shared_ptr<httpserver::http_response>(new httpserver::string_response(serializedContext));
        } catch (...) {
            std::cerr << "Exception writing serialization of the crypto context" << std::endl;
            return std::shared_ptr<httpserver::http_response>(
                    new httpserver::string_response(
                            "Exception writing serialization of the crypto context",
                            httpserver::http::http_utils::http_internal_server_error));
        }
    }
};

int main(int argc, char* argv[]) {
    httpserver::webserver ws = httpserver::create_webserver(8080);

    hello_world_resource hwr;
    ws.register_resource("/hello", &hwr);

    // Sample Program: Step 1: Set CryptoContext
    CCParams<CryptoContextBFVRNS> parameters;
    parameters.SetPlaintextModulus(65537);
    parameters.SetMultiplicativeDepth(3);
    parameters.SetBatchSize(32);

    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);
    // Enable features that you wish to use
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);

    crypto_context_resource ccr(cryptoContext);

    // Register resources and start WS
    ws.register_resource("/crypto_context", &ccr);
    ws.start(true);

    return EXIT_SUCCESS;
}