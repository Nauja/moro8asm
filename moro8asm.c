#include "moro8asm.h"

#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif

#ifdef HAVE_STDIO_H
#include <stdio.h>
#endif

#ifdef HAVE_STRING_H
#include <string.h>
#endif

typedef struct moro8asm_hooks moro8asm_hooks;

#if defined(_MSC_VER)
/* work around MSVC error C2322: '...' address of dllimport '...' is not static */
static void* MORO8ASM_CDECL internal_malloc(size_t size)
{
    return MORO8ASM_MALLOC(size);
}

static void MORO8ASM_CDECL internal_free(void* pointer)
{
    MORO8ASM_FREE(pointer);
}
#else
#define internal_malloc MORO8ASM_MALLOC
#define internal_free MORO8ASM_FREE
#endif

static moro8asm_hooks moro8asm_global_hooks = {
    internal_malloc,
    internal_free
};

void moro8asm_init_hooks(struct moro8_hooks* hooks)
{
    moro8asm_global_hooks.malloc_fn = hooks->malloc_fn;
    moro8asm_global_hooks.free_fn = hooks->free_fn;
}

#define _MORO8ASM_MALLOC moro8asm_global_hooks.malloc_fn
#define _MORO8ASM_FREE moro8asm_global_hooks.free_fn

#define MORO8ASM_TRUE 1
#define MORO8ASM_FALSE 0

typedef enum moro8asm_tok moro8asm_tok;
typedef enum moro8asm_op moro8asm_op;
typedef struct moro8asm_token moro8asm_token;

/** Map opcodes to tokens. */
static struct { const char* name; moro8asm_op op; } MORO8ASM_OP_TOKEN[] = {
    {"ADC", MORO8ASM_OP_ADC},
    {"AND", MORO8ASM_OP_AND},
    {"ASL", MORO8ASM_OP_ASL},
    {"BCC", MORO8ASM_OP_BCC},
    {"BCS", MORO8ASM_OP_BCS},
    {"BEQ", MORO8ASM_OP_BEQ},
    {"BIT", MORO8ASM_OP_BIT},
    {"BMI", MORO8ASM_OP_BMI},
    {"BNE", MORO8ASM_OP_BNE},
    {"BPL", MORO8ASM_OP_BPL},
    {"BVC", MORO8ASM_OP_BVC},
    {"BVS", MORO8ASM_OP_BVS},
    {"CLC", MORO8ASM_OP_CLC},
    {"CLV", MORO8ASM_OP_CLV},
    {"CMP", MORO8ASM_OP_CMP},
    {"CPX", MORO8ASM_OP_CPX},
    {"CPY", MORO8ASM_OP_CPY},
    {"DEA", MORO8ASM_OP_DEA},
    {"DEC", MORO8ASM_OP_DEC},
    {"DEX", MORO8ASM_OP_DEX},
    {"DEY", MORO8ASM_OP_DEY},
    {"EOR", MORO8ASM_OP_EOR},
    {"INA", MORO8ASM_OP_INA},
    {"INC", MORO8ASM_OP_INC},
    {"INX", MORO8ASM_OP_INX},
    {"INY", MORO8ASM_OP_INY},
    {"JMP", MORO8ASM_OP_JMP},
    {"JSR", MORO8ASM_OP_JSR},
    {"LDA", MORO8ASM_OP_LDA},
    {"LDX", MORO8ASM_OP_LDX},
    {"LDY", MORO8ASM_OP_LDY},
    {"LSR", MORO8ASM_OP_LSR},
    {"NOP", MORO8ASM_OP_NOP},
    {"ORA", MORO8ASM_OP_ORA},
    {"PHA", MORO8ASM_OP_PHA},
    {"PHP", MORO8ASM_OP_PHP},
    {"PLA", MORO8ASM_OP_PLA},
    {"PLP", MORO8ASM_OP_PLP},
    {"ROL", MORO8ASM_OP_ROL},
    {"ROR", MORO8ASM_OP_ROR},
    {"RTS", MORO8ASM_OP_RTS},
    {"SBC", MORO8ASM_OP_SBC},
    {"SEC", MORO8ASM_OP_SEC},
    {"STA", MORO8ASM_OP_STA},
    {"STX", MORO8ASM_OP_STX},
    {"STY", MORO8ASM_OP_STY},
    {"TAX", MORO8ASM_OP_TAX},
    {"TAY", MORO8ASM_OP_TAY},
    {"TSX", MORO8ASM_OP_TSX},
    {"TXA", MORO8ASM_OP_TXA},
    {"TYA", MORO8ASM_OP_TYA},
    {NULL, 0}
};

struct moro8asm_line_data;
typedef struct moro8asm_line_data
{
    /** Line. */
    size_t line;
    /** Label of this line. */
    struct
    {
        /** Buffer. */
        const char* begin;
        /** Size. */
        size_t size;
    } label;
    /** Opcode on this line. */
    moro8asm_op op;
    /** Next line. */
    struct moro8asm_line_data* next;
} moro8asm_line_data;

moro8asm_token* moro8asm_token_create()
{
    moro8asm_token* token = (moro8asm_token*)MORO8ASM_MALLOC(sizeof(moro8asm_token));
    if (!token)
    {
        return NULL;
    }

    token->tok = MORO8ASM_TOK_END;
    token->line = 0;
    token->col = 0;
    token->data.label.begin = NULL;
    token->data.label.size = 0;
    token->next = NULL;
    return token;
}

void moro8asm_token_delete(moro8asm_token* token)
{
    moro8asm_token* current = token;
    moro8asm_token* next = NULL;

    while (current != NULL)
    {
        next = current->next;
        current->next = NULL;
        MORO8ASM_FREE(current);
        current = next;
    }
}

static moro8asm_line_data* moro8asm_line_data_create()
{
    moro8asm_line_data* data = (moro8asm_line_data*)MORO8ASM_MALLOC(sizeof(moro8asm_line_data));
    if (!data)
    {
        return NULL;
    }

    data->line = 0;
    data->label.begin = NULL;
    data->label.size = 0;
    data->op = 0;
    data->next = NULL;
    return data;
}

static void moro8asm_line_data_delete(moro8asm_line_data* data)
{
    moro8asm_line_data* current = data;
    moro8asm_line_data* next = NULL;

    while (current != NULL)
    {
        next = current->next;
        current->next = NULL;
        MORO8ASM_FREE(current);
        current = next;
    }
}

moro8asm_token* moro8asm_tokenize(const char* buf, size_t size)
{
#define MORO8ASM_STATE_IDLE 0
#define MORO8ASM_STATE_LABEL 1
#define MORO8ASM_STATE_NUMBER 2
#define MORO8ASM_STATE_COMMENT 3
#define MORO8ASM_IS_LETTER(v) ((v >= 'a' && v <= 'z') || (v >= 'A' && v <= 'Z'))
#define MORO8ASM_IS_HEX(v) ((v >= '0' && v <= '9') || (v >= 'a' && v <= 'f') || (v >= 'A' && v <= 'F'))
#define MORO8ASM_SINGLECHAR_TOKEN(type) \
{ \
    current->tok = type; \
    current->line = line; \
    current->col = col; \
    current->next = moro8asm_token_create(); \
    current = current->next; \
}

    moro8asm_token* root = moro8asm_token_create();
    if (!root)
    {
        return NULL;
    }

    moro8asm_token* current = root;

    int state = MORO8ASM_STATE_IDLE;
    // Current character
    char c = 0;
    size_t line = 1;
    size_t col = 1;
    size_t label_size = 0;

    for (size_t i = 0; i < size; ++i, ++col, ++buf)
    {
        c = *buf;

        // Consume a label
        if (state == MORO8ASM_STATE_LABEL)
        {
            if (MORO8ASM_IS_LETTER(c) || MORO8ASM_IS_HEX(c))
            {
                ++label_size;
                continue;
            }

            // Found a non-label character
            current->tok = MORO8ASM_TOK_LABEL;
            current->data.label.size = label_size;
            for (size_t j = 0; MORO8ASM_OP_TOKEN[j].name != NULL; ++j)
            {
                if (strnicmp(MORO8ASM_OP_TOKEN[j].name, current->data.label.begin, label_size) == 0)
                {
                    current->tok = MORO8ASM_TOK_OPCODE;
                    current->data.label.begin = NULL;
                    current->data.label.size = 0;
                    current->data.op = MORO8ASM_OP_TOKEN[j].op;
                    break;
                }
            }
            current->next = moro8asm_token_create();
            current = current->next;
            state = MORO8ASM_STATE_IDLE;
        }

        // Consume a number
        if (state == MORO8ASM_STATE_NUMBER)
        {
            if (MORO8ASM_IS_HEX(c))
            {
                ++label_size;
                continue;
            }

            // Found a non-number character
            current->tok = MORO8ASM_TOK_NUMBER;
            current->data.number = strtol(current->data.label.begin, NULL, 16);
            current->next = moro8asm_token_create();
            current = current->next;
            state = MORO8ASM_STATE_IDLE;
        }

        // Consume whitespaces and newlines
        switch (c)
        {
        case '\0':
            return root;
        case ';':
            state = MORO8ASM_STATE_COMMENT;
        case ' ':
        case '\t':
        case '\r':
            continue;
        case '\n':
            state = MORO8ASM_STATE_IDLE;
            line++;
            col = 1;
            continue;
        default:
            // Skip comments
            if (state == MORO8ASM_STATE_COMMENT)
            {
                continue;
            }
            break;
        }

        // Consume special characters
        switch (c)
        {
        case ':':
            MORO8ASM_SINGLECHAR_TOKEN(MORO8ASM_TOK_COLON)
            break;
        case '(':
            MORO8ASM_SINGLECHAR_TOKEN(MORO8ASM_TOK_LPAREN)
            break;
        case ')':
            MORO8ASM_SINGLECHAR_TOKEN(MORO8ASM_TOK_RPAREN)
            break;
        case '#':
            MORO8ASM_SINGLECHAR_TOKEN(MORO8ASM_TOK_HASH)
            break;
        case ',':
            MORO8ASM_SINGLECHAR_TOKEN(MORO8ASM_TOK_COMMA)
            break;
        default:
            // Enter label or number mode
            if (MORO8ASM_IS_LETTER(c))
            {
                state = MORO8ASM_STATE_LABEL;
            }
            else if (c == '$')
            {
                state = MORO8ASM_STATE_NUMBER;
                ++col;
                ++i;
                ++buf;
            }
            else
            {
                continue;
            }

            label_size = 0;
            current->line = line;
            current->col = col;
            current->data.label.begin = buf;
            break;
        }
    }

    return root;
}

static moro8asm_line_data* moro8asm_linearize(const moro8asm_token* token)
{
    if (!token)
    {
        return NULL;
    }

    moro8asm_line_data* root = moro8asm_line_data_create();
    if (!root)
    {
        return NULL;
    }

    moro8asm_line_data* data = root;
    const moro8asm_token* next = token;
    while (next)
    {
        data->line = next->line;

        if (next->tok == MORO8ASM_TOK_LABEL)
        {
            data->label.begin = next->data.label.begin;
            data->label.size = next->data.label.size;

            if (!next->next || next->next->tok != MORO8ASM_TOK_COLON)
            {
                printf("Missing : after label");
                break;
            }

            next = next->next->next;
        }

        if (next->tok != MORO8ASM_TOK_OPCODE)
        {
            printf("Expected an opcode");
            break;
        }

        data->op = next->data.op;

        next = next->next;
    }

    return root;
}

moro8_uword* moro8asm_compile(const char* buf, size_t size, size_t* out_size)
{
    moro8asm_token* token = moro8asm_tokenize(buf, size);
    moro8asm_line_data* data = moro8asm_linearize(token);
    moro8asm_token_delete(token);
}