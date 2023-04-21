#include "FHEExtensions.h"

#include <vector>

using namespace lbcrypto;

namespace fhe_ext {
    Ciphertext<DCRTPoly> FHEExtensions::getEpsilon(
            const CryptoContext<DCRTPoly>& cryptoContext,
            const PublicKey<DCRTPoly>& publicKey,
            uint16_t size,
            size_t depth,
            uint32_t numIterations,
            double precision) {
        std::vector<double> epsi;
        for (uint16_t i = 0; i < size; ++i) {
            epsi.push_back(0.1);
        }

        auto epsilon = cryptoContext->MakeCKKSPackedPlaintext(epsi, 1, depth - 1, nullptr, size);
        epsilon->SetLength(size);

        auto ce = cryptoContext->Encrypt(publicKey, epsilon);
        auto ceAfterBootstrap = cryptoContext->EvalBootstrap(ce, numIterations, precision);

        return ceAfterBootstrap;
    }

    Ciphertext<DCRTPoly> FHEExtensions::fheSqrt(
            const CryptoContext<DCRTPoly>& cryptoContext,
            const Ciphertext<DCRTPoly>& encryptedX,
            uint16_t  iterationsCount) {
        auto a = encryptedX;
        auto c = cryptoContext->EvalSub(encryptedX, 1);

        for (int n = 0; n < iterationsCount; n++) {
            a = cryptoContext->EvalSub(a, cryptoContext->EvalMult(cryptoContext->EvalMult(a, c), 0.25));    // a[n+1] = a[n] - a[n] * c[n] / 2
            c = cryptoContext->EvalMult(cryptoContext->EvalMult(cryptoContext->EvalSquare(c), cryptoContext->EvalSub(c, 3)), 0.25); // c[n+1] = c[n]^2 * (c[n] - 3) / 4
        }

        return a;
    }

    lbcrypto::Ciphertext<lbcrypto::DCRTPoly> FHEExtensions::fheInverse(
            const CryptoContext <DCRTPoly> &cryptoContext,
            const Ciphertext <DCRTPoly> &encryptedX,
            const Ciphertext <DCRTPoly> &ceAfterBootst,
            uint16_t iterationsCount) {
        auto cb = ceAfterBootst;

        for (int i = 0; i < iterationsCount; i++) {
            auto ctemp = cryptoContext->EvalMult(cb, encryptedX); // Compute cb * ca
            ctemp = cryptoContext->EvalSub(2, ctemp); // Compute 2 - (cb * ca)
            cb = cryptoContext->EvalMult(cb, ctemp); // Compute cb * (2 - (cb * ca))
        }

        return cb;
    }

//    Ciphertext<DCRTPoly> FHEExtensions::fheInverse(
//            const CryptoContext<DCRTPoly>& cryptoContext,
//            const Ciphertext<DCRTPoly>& encryptedX,
//            int iterationsCount,
//            usint depth,
//            const PublicKey<DCRTPoly>& publicKey,
//            uint32_t numIterations,
//            uint32_t precision) {
//        std::vector<double> ePsi;
//        for (int i = 0; i < encryptedX->GetSlots(); ++i) {
//            ePsi.push_back(0.1);
//        }
//        size_t encodedLength = ePsi.size();
//
//        Plaintext epsilon = cryptoContext->MakeCKKSPackedPlaintext(ePsi, 1, depth - 1, nullptr, encodedLength);
//        epsilon->SetLength(encodedLength);
//
//        auto ce = cryptoContext->Encrypt(publicKey, epsilon);
//        auto ceAfterBootst = cryptoContext->EvalBootstrap(ce, numIterations, precision); // cb directe
//
//        auto cb = ceAfterBootst;
//
//        for (int n = 0; n < iterationsCount; n++) {
//            auto ctemp = cryptoContext->EvalMult(cb, encryptedX);    // Compute cb * ca
//            ctemp = cryptoContext->EvalSub(2, ctemp);                               // Compute 2 - (cb * ca)
//            cb = cryptoContext->EvalMult(cb, ctemp);                              // Compute cb * (2 - (cb * ca))
//        }
//
//        return cb;
//    }

    Ciphertext<DCRTPoly> FHEExtensions::fheMaxPrime(
            const CryptoContext<DCRTPoly>& cryptoContext,
            const Ciphertext<DCRTPoly>& a,
            const Ciphertext<DCRTPoly>& b) {
        auto addAB = cryptoContext->EvalAdd(a, b);  //x = (a + b) ;
        auto multSub = cryptoContext->EvalMult(addAB , 0.5); //x = (a + b) / 2;
        auto subAB = cryptoContext->EvalSub(a , b); //y = (a - b)
        auto multSub2 = cryptoContext->EvalMult(subAB , 0.5); //y = (a - b) / 2;

        auto powA_B_ = cryptoContext->EvalSquare(multSub2); // y = pow(y, 2)

        auto encryptedSqrt = fheSqrt(cryptoContext, powA_B_, 5);   //z = sqrt(pow(y, 2));

        auto maxValue = cryptoContext->EvalAdd (multSub, encryptedSqrt);

        return maxValue;
    }

    Ciphertext<DCRTPoly> FHEExtensions::fheMax(
            const CryptoContext<DCRTPoly>& cryptoContext,
            const Ciphertext<DCRTPoly>& a,
            const Ciphertext<DCRTPoly>& b,
            const Ciphertext<DCRTPoly>& ceAfterBootstrap,
            int iterationsCount) {

        auto addAB = cryptoContext->EvalAdd(a , b);  //x = (a + b) ;
        auto invAddAB = fheInverse(cryptoContext, addAB, ceAfterBootstrap, iterationsCount);

        auto a_ = cryptoContext->EvalMult(a, invAddAB);
        auto b_ = cryptoContext->EvalMult(b, invAddAB);

        auto a_b_ = fheMaxPrime(cryptoContext, a_, b_);

        auto maxValue = cryptoContext->EvalAdd (addAB, a_b_);

        return maxValue;
    }
}