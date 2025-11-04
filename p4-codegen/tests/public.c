/**
 * @file public.c
 * @brief Public test cases (and location for new tests)
 * 
 * This file provides a few basic sanity test cases and a location to add new tests.
 */

#include "testsuite.h"

#ifndef SKIP_IN_DOXYGEN

TEST_PROGRAM(D_sanity_zero, 0, "def int main() { return 0; }")

TEST_EXPRESSION(D_expr_int,   7, "7")
TEST_EXPRESSION(D_expr_add,   5, "2+3")
TEST_EXPRESSION(D_expr_long, 10, "1+2+3+4")

TEST_EXPRESSION(D_expr_sanity_zero, 0, "0")

TEST_EXPRESSION(C_expr_negate, -4, "-4")

TEST_MAIN(C_assignment, 14, "int a; a = 2 + 3 * 4; return a;")
TEST_PROGRAM(C_global_assignment, 14, "int a; def int main() { a = 2 + 3 * 4; return a; }")

TEST_BOOL_EXPRESSION(B_expr_not_t, 0, "!true")

TEST_MAIN(B_conditional, 2,
        "  int r; "
        "  if (true) { r = 2; } "
        "  else { r = 3; } "
        "  return r;")

TEST_MAIN(B_whileloop, 10,
        "  int a; a = 0; "
        "  while (a < 10) { a = a + 1; } "
        "  return a;")

TEST_PROGRAM(B_funccall, 20,
        "def int ten() { return 10; } "
        "def int main() { return ten() + ten(); }")

TEST_PROGRAM(A_funccall_params, 5,
        "def int add(int a, int b) { return a + b; } "
        "def int main() { return add(2,3); }")

#endif

/**
 * @brief Register all test cases
 * 
 * @param s Test suite to which the tests should be added
 */
void public_tests (Suite *s)
{
    TCase *tc = tcase_create ("Public");

    TEST(D_sanity_zero);
    TEST(D_expr_int);
    TEST(D_expr_add);
    TEST(D_expr_long);
    TEST(D_expr_sanity_zero);

    TEST(C_expr_negate);
    TEST(C_assignment);
    TEST(C_global_assignment);

    TEST(B_expr_not_t);
    TEST(B_conditional);
    TEST(B_whileloop);
    TEST(B_funccall);

    TEST(A_funccall_params);

    suite_add_tcase (s, tc);
}

