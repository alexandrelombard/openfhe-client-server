//
// Created by alombard on 18/04/2023.
//

#include "ExpressionTree.h"

#include <vector>

namespace fhe_parser {
    std::shared_ptr<std::vector<std::string>> tokenize(const std::string &expression) {
        int oldIdx = 0;
        int idx = 0;

        auto tokens = std::make_shared<std::vector<std::string>>();

        while (expression[idx] != '\0') {
            if(expression[idx] == '+' || expression[idx] == '-' || expression[idx] == '*' || expression[idx] == '/') {
                // FIXME Manage unary minus
                tokens->push_back(expression.substr(oldIdx, idx));
                oldIdx = idx + 1;
            }

            idx += 1;
        }

        return tokens;
    }

    ExpressionTree ExpressionTree::build(const std::string &expression) {
        // Convert the expression to a vector of tokens
        auto tokens = tokenize(expression);
    }
}