//
// Created by alombard on 18/04/2023.
//

#ifndef OPENFHE_CLIENT_SERVER_EXPRESSIONTREENODE_H
#define OPENFHE_CLIENT_SERVER_EXPRESSIONTREENODE_H

#include <string>
#include <utility>

namespace fhe_parser {

    class ExpressionTreeNode {
    public:
        ExpressionTreeNode() : left(nullptr), right(nullptr) {}
        explicit ExpressionTreeNode(std::string  val) : val(std::move(val)), left(nullptr), right(nullptr) {}

        const ExpressionTreeNode *getLeft() {
            return this->left;
        }

        const ExpressionTreeNode *getRight() {
            return this->right;
        }

        void setLeft(ExpressionTreeNode *left) {
            this->left = left;
        }

        void setRight(ExpressionTreeNode *right) {
            this->right = right;
        }

        bool isOperation() const {
            if (this->val == "+" ||
                this->val == "-" ||
                this->val == "*" ||
                this->val == "/") {
                return true;
            }

            return false;
        }
    private:
        std::string val;
        ExpressionTreeNode *left, *right;
    };

} // fhe_parser

#endif //OPENFHE_CLIENT_SERVER_EXPRESSIONTREENODE_H
