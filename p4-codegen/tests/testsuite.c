#include "testsuite.h"

jmp_buf decaf_error;

void Error_throw_printf (const char* format, ...)
{
    longjmp(decaf_error, 1);
}

long run_program (char* text)
{
    ASTNode* tree = NULL;
    if (setjmp(decaf_error) == 0) {
        /* no error */
        tree = parse(lex(text));
    } else {
        /* parsing error; return code */
        return ERROR_RETURN_CODE;
    }
    NodeVisitor_traverse_and_free(SetParentVisitor_new(), tree);
    NodeVisitor_traverse_and_free(CalcDepthVisitor_new(), tree);
    NodeVisitor_traverse_and_free(BuildSymbolTablesVisitor_new(), tree);
    ErrorList* errors = analyze(tree);
    if (!ErrorList_is_empty(errors)) {
        /* static analysis error; return code */
        return ERROR_RETURN_CODE;
    }
    NodeVisitor_traverse_and_free(AllocateSymbolsVisitor_new(), tree);
    InsnList* iloc = generate_code(tree);
    return run_simulator(iloc, false);
}

long run_main(char* text)
{
    char code[MAX_FILE_SIZE+128];
    snprintf(code, MAX_FILE_SIZE+128, "def int main() { %s }", text);
    return run_program(code);
}

long run_expression(char* text)
{
    char code[MAX_FILE_SIZE+128];
    snprintf(code, MAX_FILE_SIZE+128, "def int main() { return (%s); }", text);
    return run_program(code);
}

long run_bool_expression(char* text)
{
    char code[MAX_FILE_SIZE+128];
    snprintf(code, MAX_FILE_SIZE+128, "def int main() { if (%s) { return 1; } return 0; }", text);
    return run_program(code);
}

extern void public_tests (Suite *s);
extern void private_tests (Suite *s);

Suite * test_suite (void)
{
    Suite *s = suite_create ("Default");
    public_tests (s);
    private_tests (s);
    return s;
}

void run_testsuite (void)
{
    Suite *s = test_suite ();
    SRunner *sr = srunner_create (s);
    srunner_run_all (sr, CK_NORMAL);
    srunner_free (sr);
}

int main (void)
{
    srand((unsigned)time(NULL));
    run_testsuite ();
    return EXIT_SUCCESS;
}
