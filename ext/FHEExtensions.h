#ifndef OPENFHE_CLIENT_SERVER_FHEEXTENSIONS_H
#define OPENFHE_CLIENT_SERVER_FHEEXTENSIONS_H

#include "openfhe.h"

#include <cstdint>

namespace fhe_ext {
    class FHEExtensions {
    public:
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> getEpsilon(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly>& cryptoContext,
                const lbcrypto::PublicKey<lbcrypto::DCRTPoly>& publicKey,
                uint16_t size,
                size_t depth,
                uint32_t numIterations,
                double precision);

        /**
         * Performs an approximation of sqrt() in an homomorphic context
         * @param cryptoContext the crypto context
         * @param encryptedX the value for which sqrt() will be computed
         * @param iterationsCount the number of iterations (the higher, the better the accuracy)
         * @return the encrypted result of sqrt(encryptedX)
         */
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> sqrt(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoContext,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &encryptedX,
                uint16_t iterationsCount);

        /**
         * Performs an approximation of inverseSqrt() in an homomorphic context
         * @param cryptoContext the crypto context
         * @param encryptedX the value for which inverseSqrt() will be computed
         * @param iterationsCount the number of iterations (the higher, the better the accuracy)
         * @return the encrypted result of inverseSqrt(encryptedX)
         */
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> inverseSqrt(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoContext,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &encryptedX,
                uint16_t iterationsCount);

        /**
        * Performs an approximation of abs() in an homomorphic context
        * @param cryptoContext the crypto context
        * @param encryptedX the value for which abs() will be computed
        * @param iterationsCount the number of iterations (the higher, the better the accuracy)
        * @return the encrypted result of abs(encryptedX)
        */
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> abs(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoContext,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &encryptedX,
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
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> inverse(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoContext,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &encryptedX,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &ceAfterBootst,
                uint16_t iterationsCount);

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
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> maxPrime(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoContext,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &a,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &b);

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
        static lbcrypto::Ciphertext<lbcrypto::DCRTPoly> max(
                const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoContext,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &a,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &b,
                const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &ceAfterBootstrap,
                int iterationsCount = 12);
    };
}

#endif //OPENFHE_CLIENT_SERVER_FHEEXTENSIONS_H
