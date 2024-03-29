#include <chrono>
#include <iostream>

#include "openfhe.h"

#include "../ext/FHEExtensions.h"

#define PROFILE

using namespace lbcrypto;
using namespace fhe_ext;

int main(int argc, char *argv[]) {
    const int numSlots = 4;

//    std::cout << "Set CryptoContext has started ................. " << std::endl;
    auto start_GenContext = std::chrono::high_resolution_clock::now();

    // Step 1: Set CryptoContext
    CCParams<CryptoContextCKKSRNS> parameters;

    // A. Specify main parameters

    SecretKeyDist secretKeyDist = UNIFORM_TERNARY;
    parameters.SetSecretKeyDist(secretKeyDist);

    //A2) Desired security level based on FHE standards.


    parameters.SetSecurityLevel(HEStd_NotSet);
    parameters.SetRingDim(1024);

    /*  A3) Key switching parameters.*/
    parameters.SetNumLargeDigits(3);
    parameters.SetKeySwitchTechnique(HYBRID);

    /*  A4) Scaling parameters.
    */

    // All modes are supported for 64-bit CKKS bootstrapping.
    ScalingTechnique rescaleTech = FLEXIBLEAUTO;
    usint dcrtBits = 59;
    usint firstMod = 60;


    uint32_t numIterations = 2;

    parameters.SetScalingModSize(dcrtBits);
    parameters.SetScalingTechnique(rescaleTech);
    parameters.SetFirstModSize(firstMod);

    /*  A4) Bootstrapping parameters.
    * We set a budget for the number of levels we can consume in bootstrapping for encoding and decoding, respectively.
    * Using larger numbers of levels reduces the complexity and number of rotation keys,
    * but increases the depth required for bootstrapping.
    * We must choose values smaller than ceil(log2(slots)). A level budget of {4, 4} is good for higher ring
    * dimensions (65536 and higher).
    */
    std::vector<uint32_t> levelBudget = {1, 1};

    // We approximate the number of levels bootstrapping will consume to help set our initial multiplicative depth.
    // Each extra iteration on top of 1 requires an extra level to be consumed.
    uint32_t approxBootstrapDepth = 2 + (numIterations - 1);

    std::vector<uint32_t> bsgsDim = {0, 0};

    /*  A5) Multiplicative depth.
    * The goal of bootstrapping is to increase the number of available levels we have, or in other words,
    * to dynamically increase the multiplicative depth. However, the bootstrapping procedure itself
    * needs to consume a few levels to run. We compute the number of bootstrapping levels required
    * using GetBootstrapDepth, and add it to levelsUsedBeforeBootstrap to set our initial multiplicative
    * depth.
    */
    uint32_t levelsUsedBeforeBootstrap = 50;
    usint depth =
            levelsUsedBeforeBootstrap + FHECKKSRNS::GetBootstrapDepth(approxBootstrapDepth, levelBudget, secretKeyDist);
//    std::cout << "MultiplicativeDepth: " << depth << std::endl;
    parameters.SetMultiplicativeDepth(depth);

    // Generate crypto context.
    CryptoContext<DCRTPoly> cryptoContext = GenCryptoContext(parameters);

    auto end_GenContext = std::chrono::high_resolution_clock::now();
    auto resutlat_GenContext = std::chrono::duration_cast<std::chrono::milliseconds>(
            end_GenContext - start_GenContext); // calcul du temps écoulé
//    std::cout << "Time taken to generate the Crypto Context ==: " << resutlat_GenContext.count() << " milliseconds."
//              << std::endl; // affichage du temps écoulé en secondes



    // Enable features that you wish to use. Note, we must enable FHE to use bootstrapping.
    cryptoContext->Enable(PKE);
    cryptoContext->Enable(KEYSWITCH);
    cryptoContext->Enable(LEVELEDSHE);
    cryptoContext->Enable(ADVANCEDSHE);
    cryptoContext->Enable(FHE);

    usint ringDim = cryptoContext->GetRingDimension();
//    std::cout << "CKKS scheme is using ring dimension " << ringDim << std::endl;


//    std::cout << "Precomputations for bootstrapping has started ..................... " << std::endl;
    auto start_Bootst = std::chrono::high_resolution_clock::now();
    // Step 2: Precomputations for bootstrapping
    cryptoContext->EvalBootstrapSetup(levelBudget, bsgsDim, numSlots);

    auto end_Bootst = std::chrono::high_resolution_clock::now();
    auto resutlat_Bootst = std::chrono::duration_cast<std::chrono::milliseconds>(end_Bootst - start_Bootst);
//    std::cout << "Time taken for pre-calculation for Bootstrapping  == " << resutlat_Bootst.count() << " milliseconds."
//              << std::endl;


//    std::cout << " Key Generation has started ..................... " << std::endl;
    auto startKeyGen = std::chrono::high_resolution_clock::now();

    // Step 3: Key Generation
    auto keyPair = cryptoContext->KeyGen();
    cryptoContext->EvalMultKeyGen(keyPair.secretKey);
    // Generate bootstrapping keys.
    cryptoContext->EvalBootstrapKeyGen(keyPair.secretKey, numSlots);

    auto endKeyGen = std::chrono::high_resolution_clock::now();
    auto durationKeyGen = std::chrono::duration_cast<std::chrono::milliseconds>(
            endKeyGen - startKeyGen); // calcul du temps écoulé
//    std::cout << "Time taken for Key Generation  == " << durationKeyGen.count() << " milliseconds." << std::endl;
//
//
//    std::cout << " Set up and encoding the Plaintext has started  ..................... " << std::endl;
    auto start_encoder = std::chrono::high_resolution_clock::now();

    // Step 4: Encoding and encryption of inputs
    // Inputs
    std::vector<double> A = {0.7, 2, -3.0, -1.2};
    std::vector<double> B = {10, 13, -15.0, -5.5};


    // Encoding as plaintexts
    Plaintext ptxt1 = cryptoContext->MakeCKKSPackedPlaintext(A, 1, depth - 1, nullptr, numSlots);
    ptxt1->SetLength(A.size());
    std::cout << "Input: ptxt1=  " << ptxt1;

    Plaintext ptxt2 = cryptoContext->MakeCKKSPackedPlaintext(B, 1, depth - 1, nullptr, numSlots);
    ptxt2->SetLength(B.size());
    std::cout << "Input: ptxt2 =  " << ptxt2;

    auto endEncoder = std::chrono::high_resolution_clock::now();
    auto resultEncoder = std::chrono::duration_cast<std::chrono::milliseconds>(
            endEncoder - start_encoder); // calcul du temps écoulé
//    std::cout << "Time taken for Setup and Encoding  == " << resultEncoder.count() << " milliseconds." << std::endl;


//    std::cout << " Encrpytion the Plaintext has started  ..................... " << std::endl;
    auto startEncrypt = std::chrono::high_resolution_clock::now();
    // Encrypt the encoded vectors
    auto cipherA = cryptoContext->Encrypt(keyPair.publicKey, ptxt1);

    auto endEncrypt = std::chrono::high_resolution_clock::now();
    auto resultEncrypt = std::chrono::duration_cast<std::chrono::milliseconds>(endEncrypt - startEncrypt);
//    std::cout << "Time taken for the encryption of the first Plainttext ptxt1  == " << resultEncrypt.count()
//              << " milliseconds." << std::endl;


    auto startEncrypt2 = std::chrono::high_resolution_clock::now();
    auto cipherB = cryptoContext->Encrypt(keyPair.publicKey, ptxt2);

    auto endEncrypt2 = std::chrono::high_resolution_clock::now();
    auto resultEncrypt2 = std::chrono::duration_cast<std::chrono::milliseconds>(endEncrypt2 - startEncrypt2);
//    std::cout << "Time taken for the encryption of the second plainttext ptxt2  == " << resultEncrypt2.count()
//              << " milliseconds." << std::endl;
//
//
//    std::cout << "Initial number of levels remaining (before the bootstrapping) :" << depth - cipherA->GetLevel()
//              << "and multi depth " << parameters.GetMultiplicativeDepth() << std::endl;
//
//    std::cout << " Perform the bootstrapping operation has started ..................... " << std::endl;
    auto startPerfBootstrap = std::chrono::high_resolution_clock::now();

    // Set precision equal to empirically measured value after many test runs.
    uint32_t precision = 17; // Precision input to algorithm = 17

    // Step 5: Perform the bootstrapping operation. The goal is to increase the number of levels remaining
    // for HE computation.
    auto cipherABootst = cryptoContext->EvalBootstrap(cipherA, numIterations, precision);
//    std::cout << "Number of levels remaining after bootstrapping: " << depth - cipherABootst->GetLevel()
//              << " and multi depth " << parameters.GetMultiplicativeDepth() << std::endl
//              << std::endl;

    auto endPerfBootst1 = std::chrono::high_resolution_clock::now();
    auto resultPerfBootst1 = std::chrono::duration_cast<std::chrono::milliseconds>(
            endPerfBootst1 - startPerfBootstrap);
//    std::cout << "Time taken for the Bootstrapping operation on First Ciphertext of ptxt1 == "
//              << resultPerfBootst1.count() << " milliseconds." << std::endl;


    auto startPerfBootst2 = std::chrono::high_resolution_clock::now();
    auto cipherBBootst = cryptoContext->EvalBootstrap(cipherB, numIterations, precision);

    auto endPerfBootst2 = std::chrono::high_resolution_clock::now();
    auto resultPerfBootst2 = std::chrono::duration_cast<std::chrono::milliseconds>(
            endPerfBootst2 - startPerfBootst2);
//    std::cout << "Time taken for the Bootstrapping operation on First Ciphertext of ptxt2 == "
//              << resultPerfBootst2.count() << " milliseconds." << std::endl;


    //region A + B
    auto addResult = cryptoContext->EvalAdd(cipherABootst, cipherBBootst);

    {
        Plaintext FinalResult;
        cryptoContext->Decrypt(keyPair.secretKey, addResult, &FinalResult);
        FinalResult->SetLength(numSlots);
        std::cout << "A + B: \n\t" << FinalResult << std::endl;
    }

    std::cout << "Number of levels remaining after A + B: " << depth - cipherABootst->GetLevel()
              << " and multi depth " << parameters.GetMultiplicativeDepth() << std::endl
              << std::endl;
    //endregion

    //region Inverse Sqrt
    std::cout << "Inverse Sqrt operation has started..." << std::endl;
    auto startInvSqrt = std::chrono::high_resolution_clock::now();

    auto invSqrtResult = FHEExtensions::inverseSqrt(cryptoContext, cipherABootst, 12);

    auto endInvSqrt = std::chrono::high_resolution_clock::now();
    auto durationInvSqrt = std::chrono::duration_cast<std::chrono::milliseconds>(endInvSqrt - startInvSqrt);

    std::cout << "Time taken InverseSqrt() operation == " << durationInvSqrt.count() << " milliseconds." << std::endl;
    {
        Plaintext FinalResult;
        cryptoContext->Decrypt(keyPair.secretKey, invSqrtResult, &FinalResult);
        FinalResult->SetLength(numSlots);
        std::cout << "The InverseSqrt() of A: \n\t" << FinalResult << std::endl;
    }

    std::cout << "Number of levels remaining after sqrt(): " << depth - cipherABootst->GetLevel()
              << " and multi depth " << parameters.GetMultiplicativeDepth() << std::endl
              << std::endl;
    //endregion

    //region Sqrt
    std::cout << "Sqrt operation has started..." << std::endl;
    auto startSqrt = std::chrono::high_resolution_clock::now();

    auto sqrtResult = FHEExtensions::sqrt(cryptoContext, cipherABootst, 4);

    auto endSqrt = std::chrono::high_resolution_clock::now();
    auto durationSqrt = std::chrono::duration_cast<std::chrono::milliseconds>(endSqrt - startSqrt);

    std::cout << "Time taken Sqrt() operation == " << durationSqrt.count() << " milliseconds." << std::endl;
    {
        Plaintext FinalResult;
        cryptoContext->Decrypt(keyPair.secretKey, sqrtResult, &FinalResult);
        FinalResult->SetLength(numSlots);
        std::cout << "The Sqrt() of A: \n\t" << FinalResult << std::endl;
    }

    std::cout << "Number of levels remaining after sqrt(): " << depth - cipherABootst->GetLevel()
              << " and multi depth " << parameters.GetMultiplicativeDepth() << std::endl
              << std::endl;
    //endregion

    //region Inverse
    std::cout << "Inverse operation has started .........................." << std::endl;
    auto startInverse = std::chrono::high_resolution_clock::now();

    auto ceAfterBootst = FHEExtensions::getEpsilon(cryptoContext, keyPair.publicKey, A.size(), depth, numIterations, precision);
    auto inverseResult = FHEExtensions::inverse(cryptoContext, cipherABootst, ceAfterBootst, 12);

    auto endInverse = std::chrono::high_resolution_clock::now();
    auto durationInverse = std::chrono::duration_cast<std::chrono::milliseconds>(endInverse - startInverse);

    std::cout << "Time taken Inverse() operation == " << durationInverse.count() << " milliseconds." << std::endl;

    {
        Plaintext finalResult;
        cryptoContext->Decrypt(keyPair.secretKey, inverseResult, &finalResult);
        finalResult->SetLength(numSlots);
        std::cout << "The Inverse() of A: \n\t" << finalResult << std::endl;
    }

    std::cout << "Number of levels remaining after inverse(): " << depth - cipherABootst->GetLevel()
              << " and multi depth " << parameters.GetMultiplicativeDepth() << std::endl
              << std::endl;
    //endregion

    //region Abs value
    std::cout << "Abs value operation has started .........................." << std::endl;
    auto startAbs = std::chrono::high_resolution_clock::now();
    auto absResult = FHEExtensions::abs(cryptoContext, cipherABootst, 12);

    auto endAbs = std::chrono::high_resolution_clock::now();
    auto durationAbs  = std::chrono::duration_cast<std::chrono::milliseconds>(endAbs - startAbs);

    std::cout << "Time taken Abs() operation == " << durationAbs.count() << " milliseconds." << std::endl;

    {
        Plaintext finalResult;
        cryptoContext->Decrypt(keyPair.secretKey, absResult, &finalResult);
        finalResult->SetLength(numSlots);
        std::cout << "The Inverse() of A: \n\t" << finalResult << std::endl;
    }

    std::cout << "Number of levels remaining after abs(): " << depth - cipherABootst->GetLevel()
              << " and multi depth " << parameters.GetMultiplicativeDepth() << std::endl
              << std::endl;
    //endregion


    //region Max
    std::cout << " Max operation has started .........................." << std::endl;
    auto startMax = std::chrono::high_resolution_clock::now();

    auto resultMax = FHEExtensions::max(cryptoContext, cipherABootst, cipherBBootst, ceAfterBootst);

    auto endMax = std::chrono::high_resolution_clock::now();
    auto durationMax = std::chrono::duration_cast<std::chrono::milliseconds>(endMax - startMax);

    std::cout << "Time taken Max operation == " << durationSqrt.count() << " milliseconds." << std::endl;

    {
        Plaintext finalResult;
        cryptoContext->Decrypt(keyPair.secretKey, resultMax, &finalResult);
        finalResult->SetLength(numSlots);
        std::cout << "The Max of A and B:\n\t" << finalResult << std::endl;
    }
    //endregion

}