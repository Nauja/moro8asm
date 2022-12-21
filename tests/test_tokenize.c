#include "test_config.h"

static void test_tokenize(void **state)
{
    char buf[] = ".import abc\n\
.import def\n\
\n\
foo:\n\\
  lda #$1\n\
  lda stk,$1\n\
";

    moro8asm_tok tokens[] = {
        MORO8ASM_TOK_DOT,
        MORO8ASM_TOK_LABEL,
        MORO8ASM_TOK_LABEL,
        MORO8ASM_TOK_DOT,
        MORO8ASM_TOK_LABEL,
        MORO8ASM_TOK_LABEL,
        MORO8ASM_TOK_LABEL,
        MORO8ASM_TOK_COLON,
        MORO8ASM_TOK_OPCODE,
        MORO8ASM_TOK_HASH,
        MORO8ASM_TOK_WORD,
        MORO8ASM_TOK_OPCODE,
        MORO8ASM_TOK_LABEL,
        MORO8ASM_TOK_COMMA,
        MORO8ASM_TOK_WORD,
        MORO8ASM_TOK_END,
    };

    moro8asm_token *tok = moro8asm_tokenize(buf, 55);
    assert_non_null(tok);
    moro8asm_token *current = tok;
    size_t i = 0;
    while (current)
    {
        assert_int_equal(current->tok, tokens[i]);
        current = current->next;
        i++;
    }
    assert_int_equal(i, 16);
    moro8asm_token_delete(tok);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_tokenize)};
    return cmocka_run_group_tests(tests, NULL, NULL);
}