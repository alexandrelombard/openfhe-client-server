//
// Created by alombard on 18/04/2023.
//

#ifndef OPENFHE_CLIENT_SERVER_EXPRESSIONPARSER_H
#define OPENFHE_CLIENT_SERVER_EXPRESSIONPARSER_H

#include <string>
#include <memory>

#include "openfhe.h"

#include "ExpressionTree.h"

namespace fhe_parser {

    class ExpressionParser {
    public:
        explicit ExpressionParser(const std::string& expression) : expression(expression) {
            this->tree = ExpressionTree::build(this->expression);
        }

        std::shared_ptr<lbcrypto::Ciphertext<lbcrypto::DCRTPoly>> evaluate(
                const std::map<std::string, lbcrypto::Ciphertext<lbcrypto::DCRTPoly>>& variables);
    private:
        const std::string& expression;

        std::shared_ptr<ExpressionTree> tree;
    };

} // fhe_parser

#endif //OPENFHE_CLIENT_SERVER_EXPRESSIONPARSER_H
