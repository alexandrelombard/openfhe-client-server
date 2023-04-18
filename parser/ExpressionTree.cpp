//
// Created by alombard on 18/04/2023.
//

#include "ExpressionTree.h"

#include <vector>
#include <algorithm>

namespace fhe_parser {
    std::shared_ptr<std::vector<std::string>> tokenize(const std::string &expression) {
        int oldIdx = 0;
        int idx = 0;

        auto tokens = std::make_shared<std::vector<std::string>>();

        std::string preprocessed_expression = expression;
        preprocessed_expression.erase(std::remove_if(preprocessed_expression.begin(), preprocessed_expression.end(), ::isspace));

        while (preprocessed_expression[idx] != '\0') {
            const char c = preprocessed_expression[idx];
            if(c == '+' || c == '-' || c == '*' || c == '/') {
                // FIXME Manage unary minus
                tokens->push_back(expression.substr(oldIdx, idx));
                oldIdx = idx + 1;
            }

            idx += 1;
        }

        return tokens;
    }

    const std::shared_ptr<ExpressionTree> ExpressionTree::build(const std::string &expression) {
        // Convert the expression to a vector of tokens
        auto tokens = tokenize(expression);

        // Generate the tree from the expression
        auto expression_tree = ExpressionTree();

        return std::make_shared<ExpressionTree>(expression_tree)
    }
}