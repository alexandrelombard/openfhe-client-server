//
// Created by alombard on 18/04/2023.
//

#include "../parser/ExpressionParser.h"
#include "../parser/ExpressionTree.h"


int main(int argc, char *argv[]) {
    fhe_parser::ExpressionParser parser = fhe_parser::ExpressionParser("5 + 3 * x - x2");

    return 0;
}