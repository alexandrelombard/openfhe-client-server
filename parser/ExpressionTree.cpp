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
//        preprocessed_expression.erase(std::remove_if(preprocessed_expression.begin(), preprocessed_expression.end(), ::isspace));
        std::string::iterator end_pos = std::remove(preprocessed_expression.begin(), preprocessed_expression.end(), ' ');
        preprocessed_expression.erase(end_pos, preprocessed_expression.end());

        while (preprocessed_expression[idx] != '\0') {
            const char c = preprocessed_expression[idx];
            if(c == '+' || c == '-' || c == '*' || c == '/') {
                // FIXME Manage unary minus
                tokens->push_back(preprocessed_expression.substr(oldIdx, idx - oldIdx));  // Push the part before the operator
                tokens->push_back(preprocessed_expression.substr(idx, 1));                // Push the operator
                oldIdx = idx + 1;
            }

            idx += 1;
        }

        tokens->push_back(preprocessed_expression.substr(oldIdx, idx - oldIdx));    // Push the remaining part

        return tokens;
    }

    const std::shared_ptr<ExpressionTree> ExpressionTree::build(const std::string &expression) {
        // Convert the expression to a vector of tokens
        auto tokens = tokenize(expression);

        // Generate the tree from the expression
        auto expression_tree = ExpressionTree();

        return std::make_shared<ExpressionTree>(expression_tree);
    }
}