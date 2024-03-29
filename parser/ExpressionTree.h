//
// Created by alombard on 18/04/2023.
//

#ifndef OPENFHE_CLIENT_SERVER_EXPRESSIONTREE_H
#define OPENFHE_CLIENT_SERVER_EXPRESSIONTREE_H

#include <string>

#include "ExpressionTreeNode.h"

#include "openfhe.h"

namespace fhe_parser {
    class ExpressionTree {
    public:
        ExpressionTree() = default;
        ExpressionTree(const ExpressionTree& e) = default;
        ExpressionTree& operator=(const ExpressionTree& e) = default;

        static std::shared_ptr<ExpressionTree> build(const std::string& expression);
    private:
        ExpressionTreeNode *root;
    };
}


#endif //OPENFHE_CLIENT_SERVER_EXPRESSIONTREE_H
