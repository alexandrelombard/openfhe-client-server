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

    Ciphertext<DCRTPoly> FHEExtensions::sqrt(
            const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoContext,
            const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &encryptedX,
            uint16_t  iterationsCount) {
//        auto a = encryptedX;
//        auto c = cryptoContext->EvalSub(encryptedX, 1);
//
//        for (int n = 0; n < iterationsCount; n++) {
//            a = cryptoContext->EvalSub(a, cryptoContext->EvalMult(cryptoContext->EvalMult(a, c), 0.25));    // a[n+1] = a[n] - a[n] * c[n] / 2
//            c = cryptoContext->EvalMult(cryptoContext->EvalMult(cryptoContext->EvalSquare(c), cryptoContext->EvalSub(c, 3)), 0.25); // c[n+1] = c[n]^2 * (c[n] - 3) / 4
//        }
//
//        return a;

        // Goldschmidt's algorithm #1 for square root
        const auto& s = encryptedX;
        auto b = s;
        auto Y = cryptoContext->EvalMult(s, 0.33);
        auto x = cryptoContext->EvalMult(s, Y);
        auto y = Y;

        for (auto i = 0; i < iterationsCount; ++i) {
            b = cryptoContext->EvalMult(b, cryptoContext->EvalSquare(Y));
            Y = cryptoContext->EvalMult(0.5, cryptoContext->EvalSub(3, b));
            x = cryptoContext->EvalMult(x, Y);
            y = cryptoContext->EvalMult(y, Y);
        }

        return x;
    }

    Ciphertext<lbcrypto::DCRTPoly> FHEExtensions::inverseSqrt(
            const CryptoContext <DCRTPoly> &cryptoContext,
            const Ciphertext <DCRTPoly> &encryptedX,
            uint16_t iterationsCount) {
//        const auto& m = encryptedX;
//        auto x = cryptoContext->EvalMult(m, 2);
//
//        for(auto i = 0; i < iterationsCount; ++i) {
//            auto x2 = cryptoContext->EvalSquare(x);
//            x = cryptoContext->EvalMult(cryptoContext->EvalMult(0.5, x), cryptoContext->EvalSub(3, cryptoContext->EvalMult(m, x2)));
//        }
//
//        return x;

        // Goldschmidt's algorithm #1 for inverse square root
//        const auto& s = encryptedX;
//        auto b = s;
//        auto Y = cryptoContext->EvalMult(s, 0.33);
//        auto x = cryptoContext->EvalMult(s, Y);
//        auto y = Y;
//
//        for (auto i = 0; i < iterationsCount; ++i) {
//            b = cryptoContext->EvalMult(b, cryptoContext->EvalSquare(Y));
//            Y = cryptoContext->EvalMult(0.5, cryptoContext->EvalSub(3, b));
//            x = cryptoContext->EvalMult(x, Y);
//            y = cryptoContext->EvalMult(y, Y);
//        }
//
//        return y;

        // Goldschmidt's algorithm #2 for inverse square root
        const auto& s = encryptedX;
        const auto& estimatedInverseSqrt = cryptoContext->EvalMult(s, 0.33);
        auto x = cryptoContext->EvalMult(s, estimatedInverseSqrt);
        auto h = cryptoContext->EvalMult(0.5, estimatedInverseSqrt);
        auto r = cryptoContext->EvalMult(0.5, cryptoContext->EvalSub(1, cryptoContext->EvalMult(2, cryptoContext->EvalMult(x, h))));

        for (auto i = 0; i < iterationsCount; ++i) {
            x = cryptoContext->EvalMult(x, cryptoContext->EvalAdd(1, r));
            h = cryptoContext->EvalMult(h, cryptoContext->EvalAdd(1, r));
            r = cryptoContext->EvalMult(0.5, cryptoContext->EvalSub(1, cryptoContext->EvalMult(2, cryptoContext->EvalMult(x, h))));

            std::cout << x->GetLevel() << " " << h->GetLevel() << " " << r->GetLevel() << std::endl;

//            if (i % 3 == 1) {
                x = cryptoContext->EvalBootstrap(x, 2, 17);
                h = cryptoContext->EvalBootstrap(h, 2, 17);
                r = cryptoContext->EvalBootstrap(r, 2, 17);
//            }
        }

        return cryptoContext->EvalMult(2, h);
    }

    Ciphertext<DCRTPoly> FHEExtensions::abs(
            const CryptoContext <DCRTPoly> &cryptoContext,
            const Ciphertext <DCRTPoly> &encryptedX,
            uint16_t iterationsCount) {
        return sqrt(cryptoContext, cryptoContext->EvalSquare(encryptedX), iterationsCount);
    }

    Ciphertext<DCRTPoly> FHEExtensions::inverse(
            const CryptoContext<DCRTPoly> &cryptoContext,
            const Ciphertext<DCRTPoly> &encryptedX,
            const Ciphertext<DCRTPoly> &ceAfterBootst,
            uint16_t iterationsCount) {
        auto cb = ceAfterBootst;

        for (int i = 0; i < iterationsCount; i++) {
            auto ctemp = cryptoContext->EvalMult(cb, encryptedX); // Compute cb * ca
            ctemp = cryptoContext->EvalSub(2, ctemp); // Compute 2 - (cb * ca)
            cb = cryptoContext->EvalMult(cb, ctemp); // Compute cb * (2 - (cb * ca))
        }

        return cb;
    }

//    Ciphertext<DCRTPoly> FHEExtensions::inverse(
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

    Ciphertext<DCRTPoly> FHEExtensions::maxPrime(
            const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoContext,
            const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &a,
            const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &b) {
        auto addAB = cryptoContext->EvalAdd(a, b);  //x = (a + b) ;
        auto multSub = cryptoContext->EvalMult(addAB , 0.5); //x = (a + b) / 2;
        auto subAB = cryptoContext->EvalSub(a , b); //y = (a - b)
        auto multSub2 = cryptoContext->EvalMult(subAB , 0.5); //y = (a - b) / 2;

        auto powA_B_ = cryptoContext->EvalSquare(multSub2); // y = pow(y, 2)

        auto encryptedSqrt = sqrt(cryptoContext, powA_B_, 5);   //z = sqrt(pow(y, 2));

        auto maxValue = cryptoContext->EvalAdd (multSub, encryptedSqrt);

        return maxValue;
    }

    Ciphertext<DCRTPoly> FHEExtensions::max(
            const lbcrypto::CryptoContext<lbcrypto::DCRTPoly> &cryptoContext,
            const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &a,
            const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &b,
            const lbcrypto::Ciphertext<lbcrypto::DCRTPoly> &ceAfterBootstrap,
            int iterationsCount) {

//        auto addAB = cryptoContext->EvalAdd(a , b);  //x = (a + b) ;
//        auto invAddAB = inverse(cryptoContext, addAB, ceAfterBootstrap, iterationsCount);
//
//        auto a_ = cryptoContext->EvalMult(a, invAddAB);
//        auto b_ = cryptoContext->EvalMult(b, invAddAB);
//
//        auto a_b_ = maxPrime(cryptoContext, a_, b_);
//
//        auto maxValue = cryptoContext->EvalAdd (addAB, a_b_);
//
//        return maxValue;

        auto maxValue = cryptoContext->EvalMult(
                cryptoContext->EvalAdd(cryptoContext->EvalAdd(a, b), abs(cryptoContext, cryptoContext->EvalSub(a, b), iterationsCount)), 0.5);

        return maxValue;
    }
}