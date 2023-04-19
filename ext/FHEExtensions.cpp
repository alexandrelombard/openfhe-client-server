#include "FHEExtensions.h"

#include <vector>

using namespace lbcrypto;

namespace fhe_ext {
    Ciphertext<DCRTPoly> FHEExtensions::fheSqrt(
            const CryptoContext<DCRTPoly>& cryptoContext,
            const Ciphertext<DCRTPoly>& encryptedX,
            uint16_t  iterationsCount) {
        auto encryptedResult = encryptedX;                                   // il ne faut pas bootstraper une valeur vide sinon errors segmentation faut 11
        auto b = cryptoContext->EvalSub(encryptedX, 1);     // b = x - 1;

        for (int n = 0; n < iterationsCount; n++) {
            auto cBootst = cryptoContext->EvalMult(b, 0.5); //c = (b / 2);
            encryptedResult = cryptoContext->EvalMult(encryptedResult, cryptoContext->EvalSub(1, cBootst)); // a = a * (1 - c);
            auto fBootst = cryptoContext->EvalMult(cryptoContext->EvalSub(b, 3), 0.25);  //f = (b - 3) / 4;
            auto eBootst=  cryptoContext->EvalSquare(b);  //e = pow(b, 2);
            b = cryptoContext->EvalMult(eBootst, fBootst); //  b = e * f;
        }

        return encryptedResult;
    }

    Ciphertext<DCRTPoly> FHEExtensions::fheInverse(
            const CryptoContext<DCRTPoly>& cryptoContext,
            const Ciphertext<DCRTPoly>& encryptedX,
            int iterationsCount,
            usint depth,
            const PublicKey<DCRTPoly>& publicKey,
            uint32_t numSlots,
            uint32_t numIterations,
            uint32_t precision) {
        std::vector<double> ePsi;
        for (int i = 0; i < encryptedX->GetSlots(); ++i) {
            ePsi.push_back(0.1);
        }
        size_t encodedLength = ePsi.size();

        Plaintext epsilon = cryptoContext->MakeCKKSPackedPlaintext(ePsi);
        epsilon->SetLength(encodedLength);

        auto ce = cryptoContext->Encrypt(publicKey, epsilon);
        auto ceAfterBootst = cryptoContext->EvalBootstrap(ce, numIterations, precision); // cb directe

        auto cb = ceAfterBootst;

        for (int n = 0; n < iterationsCount; n++) {
            auto ctemp = cryptoContext->EvalMult(cb, encryptedX);    // Compute cb * ca
            ctemp = cryptoContext->EvalSub(2, ctemp);                               // Compute 2 - (cb * ca)
            cb = cryptoContext->EvalMult(cb, ctemp);                              // Compute cb * (2 - (cb * ca))
        }

        return cb;
    }

    Ciphertext<DCRTPoly> FHEExtensions::fheMax(
            const CryptoContext<DCRTPoly>& cryptoContext,
            const Ciphertext<DCRTPoly>& a,
            const Ciphertext<DCRTPoly>& b,
            int iterationsCount) {

        auto addAB = cryptoContext->EvalAdd(a , b);  //x = (a + b) ;
        auto multSub = cryptoContext->EvalMult(addAB , 0.5); //x = (a + b) / 2;
        auto sub = cryptoContext->EvalSub(a , b); //y = (a - b)
        auto multSub2 = cryptoContext->EvalMult(sub , 0.5); //y = (a - b) / 2;
        auto powAB = cryptoContext->EvalSquare(multSub2); // y = pow(y, 2)
        auto encryptedSqrt = fheSqrt(cryptoContext, powAB, iterationsCount);   //z = sqrt(pow(y, 2));
        auto maxValue = cryptoContext->EvalAdd (multSub, encryptedSqrt);

        return maxValue;

    }
}