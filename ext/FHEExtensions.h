#ifndef OPENFHE_CLIENT_SERVER_FHEEXTENSIONS_H
#define OPENFHE_CLIENT_SERVER_FHEEXTENSIONS_H

#include "openfhe.h"

#include <cstdint>

namespace fhe_ext {
    class FHEExtensions {
    public:
        /**
         * Performs an approximation of sqrt() in an homomorphic context
         * @param cryptoContext the crypto context
         * @param encryptedX the value for which sqrt() will be computed
         * @param iterationsCount the number of iterations (the higher, the better the accuracy)
         * @return the encrypted result of sqrt(encryptedX)
         */
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> fheSqrt(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cryptoContext,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& encryptedX,
                uint16_t iterationsCount);


        /**
         * Performs an approximation of the inverse function in an homomorphic context
         * @param cryptoContext the crypto context
         * @param encryptedX the value for which the inverse() will be computed
         * @param iterationsCount the number of iterations (the higher, the better the accuracy)
         * @param depth
         * @param keyPair
         * @param numSlots
         * @param numIterations
         * @param precision
         * @return the encrypted result of inverse(encryptedX)
         */
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> fheInverse(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cryptoContext,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& encryptedX,
                int iterationsCount,
                usint depth,
                const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& publicKey,
                uint32_t numSlots,
                uint32_t numIterations,
                uint32_t precision);

        /**
         * Performs an element-wise computation of the max between a and b
         * @param cryptoContext the crypto context
         * @param a the first value a
         * @param b the second value b
         * @param iterationsCount
         * @param depth
         * @param keyPair
         * @param numSlots
         * @param numIterations
         * @param precision
         * @return the element wise max of a and b
         */
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> fheMax(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cryptoContext,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& a,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly>& b,
                int iterationsCount = 12);
    };
}

#endif //OPENFHE_CLIENT_SERVER_FHEEXTENSIONS_H
