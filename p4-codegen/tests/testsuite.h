/**
 * @file testsuite.h
 * @brief Testing utility functions
 */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <time.h>

#include <check.h>

#include "p1-lexer.h"
#include "p2-parser.h"
#include "p3-analysis.h"
#include "p4-codegen.h"

/**
 * @brief Return value indicating an error
 */
#define ERROR_RETURN_CODE (-9999)

/**
 * @brief Define a test case with an entire program
 */
#define TEST_PROGRAM(NAME,RVAL,TEXT) START_TEST (NAME) \
{ ck_assert_int_eq (run_program(TEXT), RVAL); } \
END_TEST

/**
 * @brief Define a test case with only a 'main' function
 */
#define TEST_MAIN(NAME,RVAL,TEXT) START_TEST (NAME) \
{ ck_assert_int_eq (run_main(TEXT), RVAL); } \
END_TEST

/**
 * @brief Define a test case with a single integer expression
 */
#define TEST_EXPRESSION(NAME,RVAL,TEXT) START_TEST (NAME) \
{ ck_assert_int_eq (run_expression(TEXT), RVAL); } \
END_TEST

/**
 * @brief Define a test case with a single boolean expression
 */
#define TEST_BOOL_EXPRESSION(NAME,RVAL,TEXT) START_TEST (NAME) \
{ ck_assert_int_eq (run_bool_expression(TEXT), RVAL); } \
END_TEST

/**
 * @brief Add a test to the test suite
 */
#define TEST(NAME) tcase_add_test (tc, NAME)

/**
 * @brief Run lexer, parser, analysis, and code generation on given program
 *
 * @param text Code to lex, parse, analyze, and generate
 * @returns Return value or @c ERROR_RETURN_CODE if there was an error
 */
long run_program (char* text);

/**
 * @brief Run lexer, parser, analysis, and code generation on given 'main' function
 *
 * @param text Function code to lex, parse, analyze, and generate
 * @returns Return value or @c ERROR_RETURN_CODE if there was an error
 */
long run_main (char* text);

/**
 * @brief Run lexer, parser, analysis, and code generation on given integer
 * expression
 *
 * @param text Expression to lex, parse, analyze, and generate
 * @returns Return value or @c ERROR_RETURN_CODE if there was an error
 */
long run_expression (char* text);

/**
 * @brief Run lexer, parser, analysis, and code generation on given boolean
 * expression
 *
 * @param text Expression to lex, parse, analyze, and generate
 * @returns Return value or @c ERROR_RETURN_CODE if there was an error
 */
long run_bool_expression (char* text);
