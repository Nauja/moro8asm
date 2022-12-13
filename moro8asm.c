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

MORO8ASM_PUBLIC(void) moro8asm_init_hooks(struct moro8asm_hooks* hooks)
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
typedef enum moro8_opcode moro8_opcode;
typedef enum moro8asm_addr moro8asm_addr;
typedef enum moro8asm_label_type moro8asm_label_type;
typedef struct moro8asm_token moro8asm_token;
typedef struct moro8asm_instruction moro8asm_instruction;
typedef struct moro8asm_label_ref moro8asm_label_ref;
typedef struct moro8asm_module moro8asm_module;
typedef struct moro8asm_program moro8asm_program;

static char* moro8asm_strncpy(const char* buf, size_t size)
{
    char* out = (char*)MORO8ASM_MALLOC(size + 1);
    memcpy(out, buf, size);
    out[size] = '\0';
    return out;
}

#define moro8asm_strlen strlen

static int moro8asm_strnicmp(const char* left, const char* right, size_t size)
{
    if (left == right)
    {
        return 0;
    }

    if (left == NULL)
    {
        return -1;
    }

    if (right == NULL)
    {
        return 1;
    }

    int diff = 0;
    char c1 = 0;
    char c2 = 0;
    for (size_t i = 0; i < size; ++i)
    {
        c1 = left[i];
        c2 = right[i];

        if (c1 == '\0' && c2 == '\0')
        {
            return 0;
        }

        if (c1 == '\0')
        {
            return -1;
        }

        if (c2 == '\0')
        {
            return 1;
        }

        if (c1 >= 'A' && c1 <= 'Z')
        {
            c1 = 'a' + (c1 - 'A');
        }

        if (c2 >= 'A' && c2 <= 'Z')
        {
            c2 = 'a' + (c2 - 'A');
        }

        diff = c1 - c2;

        if (diff != 0)
        {
            return diff;
        }
    }

    return 0;
}

static int moro8asm_stricmp(const char* left, const char* right)
{
    size_t size = 0;
    for (; right[size] != '\0'; ++size);
    return moro8asm_strnicmp(left, right, size);
}

/** Map opcodes to tokens. */
static const char* MORO8ASM_OP_TOKEN[MORO8ASM_OP_MAX] = {
    "ADC",
    "AND",
    "ASL",
    "BCC",
    "BCS",
    "BEQ",
    "BIT",
    "BMI",
    "BNE",
    "BPL",
    "BVC",
    "BVS",
    "CLC",
    "CLV",
    "CMP",
    "CPX",
    "CPY",
    "DEA",
    "DEC",
    "DEX",
    "DEY",
    "EOR",
    "INA",
    "INC",
    "INX",
    "INY",
    "JMP",
    "JSR",
    "LDA",
    "LDX",
    "LDY",
    "LSR",
    "NOP",
    "ORA",
    "PHA",
    "PHP",
    "PLA",
    "PLP",
    "ROL",
    "ROR",
    "RTS",
    "SBC",
    "SEC",
    "STA",
    "STX",
    "STY",
    "TAX",
    "TAY",
    "TSX",
    "TXA",
    "TYA",
    "DCB"
};

/** Map opcodes to addressing mode. */
static moro8_opcode MORO8ASM_OP_MODE[MORO8ASM_OP_MAX][MORO8ASM_ADDR_MAX] = {
//  {ABS, ABS_X, ABS_Y, IMM, IMPLIED, IND, IND_X, IND_Y, ZP, ZP_X, ZP_Y}
    {MORO8_OP_ADC_ABS, MORO8_OP_ADC_ABS_X, MORO8_OP_ADC_ABS_Y, MORO8_OP_ADC_IMM, 0, 0, MORO8_OP_ADC_IND_X, MORO8_OP_ADC_IND_Y, MORO8_OP_ADC_ZP, MORO8_OP_ADC_ZP_X, 0},
    {MORO8_OP_AND_ABS, MORO8_OP_AND_ABS_X, MORO8_OP_AND_ABS_Y, MORO8_OP_AND_IMM, 0, 0, MORO8_OP_AND_IND_X, MORO8_OP_AND_IND_Y, MORO8_OP_AND_ZP, MORO8_OP_AND_ZP_X, 0},
    {MORO8_OP_ASL_ABS, MORO8_OP_ASL_ABS_X, 0, 0, MORO8_OP_ASL_AC, 0, 0, 0, MORO8_OP_ASL_ZP, MORO8_OP_ASL_ZP_X, 0},
    {MORO8_OP_BCC},
    {MORO8_OP_BCS},
    {MORO8_OP_BEQ},
    {MORO8_OP_BIT_ABS, 0, 0, 0, 0, 0, 0, 0, MORO8_OP_BIT_ZP, 0, 0},
    {MORO8_OP_BMI},
    {MORO8_OP_BNE},
    {MORO8_OP_BPL},
    {MORO8_OP_BVC},
    {MORO8_OP_BVS},
    {0, 0, 0, 0, MORO8_OP_CLC},
    {0, 0, 0, 0, MORO8_OP_CLV},
    {MORO8_OP_CMP_ABS, MORO8_OP_CMP_ABS_X, MORO8_OP_CMP_ABS_Y, MORO8_OP_CMP_IMM, 0, 0, MORO8_OP_CMP_IND_X, MORO8_OP_CMP_IND_Y, MORO8_OP_CMP_ZP, MORO8_OP_CMP_ZP_X, 0},
    {MORO8_OP_CPX_ABS, 0, 0, MORO8_OP_CPX_IMM, 0, 0, 0, 0, MORO8_OP_CPX_ZP, 0, 0},
    {MORO8_OP_CPY_ABS, 0, 0, MORO8_OP_CPY_IMM, 0, 0, 0, 0, MORO8_OP_CPY_ZP, 0, 0},
    {0, 0, 0, 0, MORO8_OP_DEA},
    {MORO8_OP_DEC_ABS, MORO8_OP_DEC_ABS_X, 0, 0, 0, 0, 0, 0, MORO8_OP_DEC_ZP, MORO8_OP_DEC_ZP_X, 0},
    {0, 0, 0, 0, MORO8_OP_DEX},
    {0, 0, 0, 0, MORO8_OP_DEY},
    {MORO8_OP_EOR_ABS, MORO8_OP_EOR_ABS_X, MORO8_OP_EOR_ABS_Y, MORO8_OP_EOR_IMM, 0, 0, MORO8_OP_EOR_IND_X, MORO8_OP_EOR_IND_Y, MORO8_OP_EOR_ZP, MORO8_OP_EOR_ZP_X, 0},
    {0, 0, 0, 0, MORO8_OP_INA},
    {MORO8_OP_INC_ABS, MORO8_OP_INC_ABS_X, 0, 0, 0, 0, 0, 0, MORO8_OP_INC_ZP, MORO8_OP_INC_ZP_X, 0},
    {0, 0, 0, 0, MORO8_OP_INX},
    {0, 0, 0, 0, MORO8_OP_INY},
    {MORO8_OP_JMP_ABS, MORO8_OP_JMP_ABS_X, 0, 0, 0, MORO8_OP_JMP_IND},
    {MORO8_OP_JSR_ABS},
    {MORO8_OP_LDA_ABS, MORO8_OP_LDA_ABS_X, MORO8_OP_LDA_ABS_Y, MORO8_OP_LDA_IMM, 0, 0, MORO8_OP_LDA_IND_X, MORO8_OP_LDA_IND_Y, MORO8_OP_LDA_ZP, MORO8_OP_LDA_ZP_X, 0},
    {MORO8_OP_LDX_ABS, 0, MORO8_OP_LDX_ABS_Y, MORO8_OP_LDX_IMM, 0, 0, 0, 0, MORO8_OP_LDX_ZP, 0, MORO8_OP_LDX_ZP_Y},
    {MORO8_OP_LDY_ABS, MORO8_OP_LDY_ABS_X, 0, MORO8_OP_LDY_IMM, 0, 0, 0, 0, MORO8_OP_LDY_ZP, MORO8_OP_LDY_ZP_X, 0},
    {MORO8_OP_LSR_ABS, MORO8_OP_LSR_ABS_X, 0, 0, MORO8_OP_LSR_AC, 0, 0, 0, MORO8_OP_LSR_ZP, MORO8_OP_LSR_ZP_X, 0},
    {0, 0, 0, 0, MORO8_OP_NOP},
    {MORO8_OP_ORA_ABS, MORO8_OP_ORA_ABS_X, MORO8_OP_ORA_ABS_Y, MORO8_OP_ORA_IMM, 0, 0, MORO8_OP_ORA_IND_X, MORO8_OP_ORA_IND_Y, MORO8_OP_ORA_ZP, MORO8_OP_ORA_ZP_X, 0},
    {0, 0, 0, 0, MORO8_OP_PHA},
    {0, 0, 0, 0, MORO8_OP_PHP},
    {0, 0, 0, 0, MORO8_OP_PLA},
    {0, 0, 0, 0, MORO8_OP_PLP},
    {MORO8_OP_ROL_ABS, MORO8_OP_ROL_ABS_X, 0, 0, MORO8_OP_ROL_AC, 0, 0, 0, MORO8_OP_ROL_ZP, MORO8_OP_ROL_ZP_X, 0},
    {MORO8_OP_ROR_ABS, MORO8_OP_ROR_ABS_X, 0, 0, MORO8_OP_ROR_AC, 0, 0, 0, MORO8_OP_ROR_ZP, MORO8_OP_ROR_ZP_X, 0},
    {0, 0, 0, 0, MORO8_OP_RTS, 0, 0, 0, 0, 0, 0},
    {MORO8_OP_SBC_ABS, MORO8_OP_SBC_ABS_X, MORO8_OP_SBC_ABS_Y, MORO8_OP_SBC_IMM, 0, 0, MORO8_OP_SBC_IND_X, MORO8_OP_SBC_IND_Y, MORO8_OP_SBC_ZP, MORO8_OP_SBC_ZP_X, 0},
    {0, 0, 0, 0, MORO8_OP_SEC, 0, 0, 0, 0, 0, 0},
    {MORO8_OP_STA_ABS, MORO8_OP_STA_ABS_X, MORO8_OP_STA_ABS_Y, 0, 0, 0, MORO8_OP_STA_IND_X, MORO8_OP_STA_IND_Y, MORO8_OP_STA_ZP, MORO8_OP_STA_ZP_X, 0},
    {MORO8_OP_STX_ABS, 0, 0, 0, 0, 0, 0, 0, MORO8_OP_STX_ZP, 0, MORO8_OP_STX_ZP_Y},
    {MORO8_OP_STY_ABS, 0, 0, 0, 0, 0, 0, 0, MORO8_OP_STY_ZP, MORO8_OP_STY_ZP_X, 0},
    {0, 0, 0, 0, MORO8_OP_TAX},
    {0, 0, 0, 0, MORO8_OP_TAY},
    {0, 0, 0, 0, MORO8_OP_TSX},
    {0, 0, 0, 0, MORO8_OP_TXA},
    {0, 0, 0, 0, MORO8_OP_TYA},
    {0}
};

/** Indicate which opcode is a branch. */
static char MORO8ASM_OP_BRANCH[MORO8ASM_OP_MAX] = {
    0,
    0,
    0,
    1, // BCC
    1, 
    1, 
    0, // BIT
    1, 
    1, 
    1, 
    1,
    1, // BVS
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0
};

MORO8ASM_PUBLIC(moro8asm_token*) moro8asm_token_create()
{
    moro8asm_token* token = (moro8asm_token*)MORO8ASM_MALLOC(sizeof(moro8asm_token));
    if (!token)
    {
        return NULL;
    }

    moro8asm_token_init(token);
    return token;
}

MORO8ASM_PUBLIC(void) moro8asm_token_init(moro8asm_token* token)
{
    memset(token, 0, sizeof(moro8asm_token));
}

MORO8ASM_PUBLIC(void) moro8asm_token_delete(moro8asm_token* token)
{
    moro8asm_token* current = token;
    moro8asm_token* next = NULL;

    while (current != NULL)
    {
        next = current->next;
        current->next = NULL;
        if (current->tok == MORO8ASM_TOK_LABEL)
        {
            MORO8ASM_FREE(current->data.label);
        }
        current->data.label = NULL;
        MORO8ASM_FREE(current);
        current = next;
    }
}

MORO8ASM_PUBLIC(moro8asm_instruction*) moro8asm_instruction_create()
{
    moro8asm_instruction* instruction = (moro8asm_instruction*)MORO8ASM_MALLOC(sizeof(moro8asm_instruction));
    if (!instruction)
    {
        return NULL;
    }

    moro8asm_instruction_init(instruction);
    return instruction;
}

MORO8ASM_PUBLIC(void) moro8asm_instruction_init(struct moro8asm_instruction* instruction)
{
    memset(instruction, 0, sizeof(moro8asm_instruction));
}

MORO8ASM_PUBLIC(void) moro8asm_instruction_delete(moro8asm_instruction* instruction)
{
    moro8asm_instruction* current = instruction;
    moro8asm_instruction* next = NULL;

    while (current != NULL)
    {
        next = current->next;
        current->next = NULL;
        MORO8ASM_FREE(current);
        current = next;
    }
}

MORO8ASM_PUBLIC(moro8_udword) moro8asm_instruction_get_pc(const moro8asm_instruction* instruction)
{
    return instruction->pc;
}

MORO8ASM_PUBLIC(size_t) moro8asm_instruction_get_line(const moro8asm_instruction* instruction)
{
    return instruction->line;
}

MORO8ASM_PUBLIC(moro8_uword) moro8asm_instruction_get_size(const moro8asm_instruction* instruction)
{
    return instruction->size;
}

MORO8ASM_PUBLIC(moro8asm_instruction*) moro8asm_instruction_get_next(const moro8asm_instruction* instruction)
{
    return instruction->next;
}

MORO8ASM_PUBLIC(moro8asm_label_ref*) moro8asm_label_ref_create()
{
    moro8asm_label_ref* ref = (moro8asm_label_ref*)MORO8ASM_MALLOC(sizeof(moro8asm_label_ref));
    if (!ref)
    {
        return NULL;
    }

    moro8asm_label_ref_init(ref);
    return ref;
}

MORO8ASM_PUBLIC(void) moro8asm_label_ref_init(moro8asm_label_ref* ref)
{
    memset(ref, 0, sizeof(moro8asm_label_ref));
}

MORO8ASM_PUBLIC(void) moro8asm_label_ref_delete(moro8asm_label_ref* ref)
{
    moro8asm_label_ref* current = ref;
    moro8asm_label_ref* next = NULL;

    while (current != NULL)
    {
        next = current->next;
        current->next = NULL;
        MORO8ASM_FREE(current->label);
        current->label = NULL;
        MORO8ASM_FREE(current);
        current = next;
    }
}

MORO8ASM_PUBLIC(struct moro8asm_module*) moro8asm_module_create()
{
    moro8asm_module* module = (moro8asm_module*)MORO8ASM_MALLOC(sizeof(moro8asm_module));
    if (!module)
    {
        return NULL;
    }

    moro8asm_module_init(module);
    return module;
}

MORO8ASM_PUBLIC(void) moro8asm_module_init(struct moro8asm_module* module)
{
    memset(module, 0, sizeof(moro8asm_module));
}

MORO8ASM_PUBLIC(void) moro8asm_module_delete(struct moro8asm_module* module)
{
    moro8asm_module* current = module;
    moro8asm_module* next = NULL;

    while (current != NULL)
    {
        next = current->next;
        current->next = NULL;
        moro8asm_label_ref_delete(module->labels);
        module->labels = NULL;
        MORO8ASM_FREE(current);
        current = next;
    }
}

static void moro8asm_module_add_label_type(moro8asm_module* module, const char* label, moro8asm_instruction* line, moro8asm_label_type type)
{
    if (moro8asm_module_find_label(module, label))
    {
        return;
    }

    moro8asm_label_ref* ref = moro8asm_label_ref_create();
    ref->module = module;
    ref->type = type;
    ref->label = moro8asm_strncpy(label, moro8asm_strlen(label));
    ref->instruction = line;
    ref->next = module->labels;
    module->labels = ref;
    module->num_labels++;
}

MORO8ASM_PUBLIC(void) moro8asm_module_add_import(moro8asm_module* module, const char* label)
{
    moro8asm_module_add_label_type(module, label, NULL, MORO8ASM_LABEL_TYPE_IMPORT);
}

MORO8ASM_PUBLIC(void) moro8asm_module_add_export(moro8asm_module* module, const char* label)
{
    moro8asm_module_add_label_type(module, label, NULL, MORO8ASM_LABEL_TYPE_EXPORT);
}

MORO8ASM_PUBLIC(void) moro8asm_module_add_label(moro8asm_module* module, const char* label, moro8asm_instruction* line)
{
    moro8asm_module_add_label_type(module, label, line, MORO8ASM_LABEL_TYPE_LOCAL);
}

MORO8ASM_PUBLIC(size_t) moro8asm_module_num_labels(const moro8asm_module* module)
{
    return module->num_labels;
}

MORO8ASM_PUBLIC(moro8asm_label_ref*) moro8asm_module_find_label(moro8asm_module* module, const char* label)
{
    if (!module->labels)
    {
        return NULL;
    }

    moro8asm_label_ref* ref = module->labels;
    while (ref)
    {
        if (moro8asm_stricmp(ref->label, label) == 0)
        {
            return ref;
        }

        ref = ref->next;
    }

    return NULL;
}

MORO8ASM_PUBLIC(moro8asm_label_ref*) moro8asm_module_get_label(const moro8asm_module* module, size_t index)
{
    moro8asm_label_ref* ptr = module->labels;
    for (size_t i = 0; i < index && ptr; ++i) ptr = ptr->next;
    return ptr;
}

MORO8ASM_PUBLIC(moro8asm_instruction*) moro8asm_module_get_line(const moro8asm_module* module, size_t index)
{
    moro8asm_instruction* ptr = module->lines;
    for (size_t i = 0; i < index && ptr; ++i) ptr = ptr->next;
    return ptr;
}

MORO8ASM_PUBLIC(size_t) moro8asm_module_num_lines(const moro8asm_module* module)
{
    return module->num_lines;
}

MORO8ASM_PUBLIC(moro8asm_module*) moro8asm_module_load(moro8asm_module* module, const char* buf, size_t size)
{
    moro8asm_token* token = moro8asm_tokenize(buf, size);
    if (!token)
    {
        return NULL;
    }

    // Placeholder instruction for the while loop
    module->lines = moro8asm_instruction_create();
    if (!module->lines)
    {
        moro8asm_token_delete(token);
        return NULL;
    }

    moro8asm_instruction* data = module->lines;
    const moro8asm_token* next = token;
    while (next)
    {
        if (next->tok == MORO8ASM_TOK_END)
        {
            break;
        }

        // Parse * = $FFFF ! probably outdated
        if (next->tok == MORO8ASM_TOK_STAR)
        {
            next = next->next;
            if (!next || next->tok != MORO8ASM_TOK_EQUAL)
            {
                printf("Missing = after *");
                break;
            }

            next = next->next;
            if (!next || (next->tok != MORO8ASM_TOK_WORD && next->tok != MORO8ASM_TOK_DWORD))
            {
                printf("Expected number after * =");
                break;
            }

            next = next->next;
        }

        // Push a new instruction
        data->next = moro8asm_instruction_create();
        module->num_lines++;
        data = data->next;

        // There is a label on this line
        if (next->tok == MORO8ASM_TOK_LABEL)
        {
            data->label = next->data.label;

            if (!next->next || next->next->tok != MORO8ASM_TOK_COLON)
            {
                printf("Missing : after label");
                break;
            }

            moro8asm_module_add_label(module, data->label, data);

            next = next->next->next;
        }

        // Parse opcode
        if (next->tok != MORO8ASM_TOK_OPCODE)
        {
            printf("Expected an opcode");
            break;
        }

        data->line = next->line;
        data->op = next->data.op;
        next = next->next;
        if (!moro8asm_parse_instruction(data, next, &next))
        {
            printf("Failed to parse opcode");
            break;
        }
    }

    // Delete the first placeholder instruction
    data = module->lines->next;
    module->lines->next = NULL;
    moro8asm_instruction_delete(module->lines);
    module->lines = data;
    moro8asm_token_delete(token);
    return module;
}

static void moro8asm_module_unlink(moro8asm_module* module)
{
    moro8asm_label_ref* current = module->labels;
    while (current)
    {
        current->address = 0;
        current = current->next;
    }
}

MORO8ASM_PUBLIC(moro8asm_program*) moro8asm_program_create()
{
    moro8asm_program* program = (moro8asm_program*)MORO8ASM_MALLOC(sizeof(moro8asm_program));
    if (!program)
    {
        return NULL;
    }

    moro8asm_program_init(program);
    return program;
}

MORO8ASM_PUBLIC(void) moro8asm_program_init(struct moro8asm_program* program)
{
    memset(program, 0, sizeof(moro8asm_program));
}

MORO8ASM_PUBLIC(void) moro8asm_program_delete(struct moro8asm_program* program)
{
    moro8asm_module_delete(program->modules);
    program->modules = NULL;
    MORO8ASM_FREE(program);
}

MORO8ASM_PUBLIC(void) moro8asm_program_add_module(struct moro8asm_program* program, struct moro8asm_module* module)
{
    module->next = program->modules;
    program->modules = module;
    program->num_modules++;
}

MORO8ASM_PUBLIC(moro8_udword) moro8asm_program_size(const moro8asm_program* program)
{
    return 0;
}

static void moro8asm_program_unlink(moro8asm_program* program)
{
    moro8asm_module* current = program->modules;
    while (current)
    {
        moro8asm_module_unlink(current);
        current = current->next;
    }
}

MORO8ASM_PUBLIC(moro8asm_token*) moro8asm_tokenize(const char* buf, size_t size)
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
            if (MORO8ASM_IS_LETTER(c) || MORO8ASM_IS_HEX(c) || c == '_')
            {
                ++label_size;
                continue;
            }

            // Found a non-label character
            current->tok = MORO8ASM_TOK_LABEL;

            // Check for x token
            if (moro8asm_strnicmp("x", current->data.label, label_size) == 0)
            {
                current->tok = MORO8ASM_TOK_X;
                current->data.label = NULL;
            }
            // Check for y token
            else if (moro8asm_strnicmp("y", current->data.label, label_size) == 0)
            {
                current->tok = MORO8ASM_TOK_Y;
                current->data.label = NULL;
            }
            else
            {
                // Check for opcode token
                for (moro8asm_op j = 0; j < MORO8ASM_OP_MAX; ++j)
                {
                    if (moro8asm_strnicmp(MORO8ASM_OP_TOKEN[j], current->data.label, label_size) == 0)
                    {
                        current->tok = MORO8ASM_TOK_OPCODE;
                        current->data.label = NULL;
                        current->data.op = j;
                        break;
                    }
                }
            }

            if (current->tok == MORO8ASM_TOK_LABEL)
            {
                current->data.label = moro8asm_strncpy(current->data.label, label_size);
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
            current->tok = label_size <= 2 ? MORO8ASM_TOK_WORD : MORO8ASM_TOK_DWORD;
            current->data.number = strtol(current->data.label, NULL, 16);
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
        case '*':
            MORO8ASM_SINGLECHAR_TOKEN(MORO8ASM_TOK_STAR)
            break;
        case '=':
            MORO8ASM_SINGLECHAR_TOKEN(MORO8ASM_TOK_EQUAL)
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

            label_size = 1;
            current->line = line;
            current->col = col;
            current->data.label = buf;
            break;
        }
    }

    return root;
}

/** Parses the dcb instruction. */
static int moro8asm_parse_dcb(moro8asm_instruction* instruction, const moro8asm_token* token, const moro8asm_token** out_token)
{
    if (instruction->op != MORO8ASM_OP_DCB)
    {
        return MORO8ASM_FALSE;
    }

    if (!token)
    {
        return MORO8ASM_FALSE;
    }

    if (token->tok != MORO8ASM_TOK_WORD)
    {
        return MORO8ASM_FALSE;
    }

    instruction->size = 0;
    instruction->operand = token;

    while (token->tok == MORO8ASM_TOK_WORD)
    {
        instruction->size++;

        token = token->next;
        if (!token || token->tok != MORO8ASM_TOK_COMMA)
        {
            break;
        }

        token = token->next;
        if (!token || token->tok != MORO8ASM_TOK_WORD)
        {
            return MORO8ASM_FALSE;
        }
    }

    *out_token = token;
    return MORO8ASM_TRUE;
}

/** Parses a branch instruction. */
static int moro8asm_parse_branch(moro8asm_instruction* instruction, const moro8asm_token* token, const moro8asm_token** out_token)
{
    if (!MORO8ASM_OP_BRANCH[instruction->op])
    {
        return MORO8ASM_FALSE;
    }

    if (!token)
    {
        return MORO8ASM_FALSE;
    }

    if (token->tok != MORO8ASM_TOK_LABEL)
    {
        return MORO8ASM_FALSE;
    }

    instruction->mode = MORO8ASM_ADDR_ABS;
    instruction->size = 2;
    instruction->operand = token;

    *out_token = token->next;
    return MORO8ASM_TRUE;
}

/** Parses an instruction using absolute mode. */
static int moro8asm_parse_abs(moro8asm_instruction* instruction, const moro8asm_token* token, const moro8asm_token** out_token)
{
    if (!token)
    {
        return MORO8ASM_FALSE;
    }

    if (token->tok != MORO8ASM_TOK_LABEL && token->tok != MORO8ASM_TOK_DWORD)
    {
        return MORO8ASM_FALSE;
    }

    const moro8asm_token* operand = token;
    moro8asm_addr mode = MORO8ASM_ADDR_ABS;

    token = token->next;
    if (token && token->tok == MORO8ASM_TOK_COMMA)
    {
        token = token->next;
        if (!token)
        {
            return MORO8ASM_FALSE;
        }

        if (token->tok == MORO8ASM_TOK_X)
        {
            mode = MORO8ASM_ADDR_ABS_X;
        }
        else if (token->tok == MORO8ASM_TOK_Y)
        {
            mode = MORO8ASM_ADDR_ABS_Y;
        }
        else
        {
            return MORO8ASM_FALSE;
        }

        token = token->next;
    }

    if (!MORO8ASM_OP_MODE[instruction->op][mode])
    {
        return MORO8ASM_FALSE;
    }

    instruction->mode = mode;
    instruction->size = 3;
    instruction->operand = operand;

    *out_token = token;
    return MORO8ASM_TRUE;
}

/** Parses an instruction using immediate mode. */
static int moro8asm_parse_imm(moro8asm_instruction* instruction, const moro8asm_token* token, const moro8asm_token** out_token)
{
    if (!token)
    {
        return MORO8ASM_FALSE;
    }

    if (token->tok != MORO8ASM_TOK_HASH)
    {
        return MORO8ASM_FALSE;
    }

    token = token->next;
    if (!token)
    {
        return MORO8ASM_FALSE;
    }
    
    if (token->tok != MORO8ASM_TOK_LABEL && token->tok != MORO8ASM_TOK_WORD)
    {
        return MORO8ASM_FALSE;
    }

    if (!MORO8ASM_OP_MODE[instruction->op][MORO8ASM_ADDR_IMM])
    {
        return MORO8ASM_FALSE;
    }

    instruction->mode = MORO8ASM_ADDR_IMM;
    instruction->size = 2;
    instruction->operand = token;

    *out_token = token->next;
    return MORO8ASM_TRUE;
}

/** Parses an instruction using zero page mode. */
static int moro8asm_parse_zp(moro8asm_instruction* instruction, const moro8asm_token* token, const moro8asm_token** out_token)
{
    if (!token)
    {
        return MORO8ASM_FALSE;
    }

    if (token->tok != MORO8ASM_TOK_WORD)
    {
        return MORO8ASM_FALSE;
    }

    const moro8asm_token* operand = token;
    moro8asm_addr mode = MORO8ASM_ADDR_ZP;

    token = token->next;
    if (token && token->tok == MORO8ASM_TOK_COMMA)
    {
        token = token->next;
        if (!token)
        {
            return MORO8ASM_FALSE;
        }

        if (token->tok == MORO8ASM_TOK_X)
        {
            mode = MORO8ASM_ADDR_ZP_X;
        }
        else if (token->tok == MORO8ASM_TOK_Y)
        {
            mode = MORO8ASM_ADDR_ZP_Y;
        }
        else
        {
            return MORO8ASM_FALSE;
        }

        token = token->next;
    }

    if (!MORO8ASM_OP_MODE[instruction->op][mode])
    {
        return MORO8ASM_FALSE;
    }

    instruction->mode = mode;
    instruction->size = 2;
    instruction->operand = operand;

    *out_token = token;
    return MORO8ASM_TRUE;
}

/** Parses an instruction using implied mode. */
static int moro8asm_parse_implied(moro8asm_instruction* instruction, const moro8asm_token* token, const moro8asm_token** out_token)
{
    if (!MORO8ASM_OP_MODE[instruction->op][MORO8ASM_ADDR_IMPLIED])
    {
        return MORO8ASM_FALSE;
    }

    instruction->mode = MORO8ASM_ADDR_IMPLIED;
    instruction->size = 1;
    *out_token = token;

    if (!token)
    {
        return MORO8ASM_TRUE;
    }

    if (token->tok == MORO8ASM_TOK_LABEL || token->tok == MORO8ASM_TOK_OPCODE)
    {
        return MORO8ASM_TRUE;
    }

    return MORO8ASM_FALSE;
}

/** Parses an instruction using indirect mode. */
static int moro8asm_parse_ind(moro8asm_instruction* instruction, const moro8asm_token* token, const moro8asm_token** out_token)
{
    if (!token || token->tok != MORO8ASM_TOK_LPAREN)
    {
        return MORO8ASM_FALSE;
    }

    token = token->next;
    if (!token || token->tok != MORO8ASM_TOK_WORD)
    {
        return MORO8ASM_FALSE;
    }

    const moro8asm_token* operand = token;
    moro8asm_addr mode = MORO8ASM_ADDR_IND;

    token = token->next;
    if (!token)
    {
        return MORO8ASM_FALSE;
    } 
    
    if (token->tok == MORO8ASM_TOK_COMMA)
    {
        token = token->next;
        if (!token || token->tok != MORO8ASM_TOK_X)
        {
            return MORO8ASM_FALSE;
        }

        token = token->next;
        if (!token || token->tok != MORO8ASM_TOK_RPAREN)
        {
            return MORO8ASM_FALSE;
        }

        mode = MORO8ASM_ADDR_IND_X;
        token = token->next;
    }
    else if (token->tok == MORO8ASM_TOK_RPAREN)
    {
        token = token->next;
        if (token && token->tok == MORO8ASM_TOK_COMMA)
        {
            token = token->next;
            if (!token || token->tok != MORO8ASM_TOK_Y)
            {
                return MORO8ASM_FALSE;
            }

            mode = MORO8ASM_ADDR_IND_Y;
            token = token->next;
        }
    }

    if (!MORO8ASM_OP_MODE[instruction->op][mode])
    {
        return MORO8ASM_FALSE;
    }

    instruction->mode = mode;
    instruction->size = 2;
    instruction->operand = operand;

    *out_token = token;
    return MORO8ASM_TRUE;
}

/** Parses an instruction. */
static int moro8asm_parse_instruction(moro8asm_instruction* instruction, const moro8asm_token* token, const moro8asm_token** out_token)
{
    if (moro8asm_parse_dcb(instruction, token, out_token) ||
        moro8asm_parse_branch(instruction, token, out_token) ||
        moro8asm_parse_abs(instruction, token, out_token) ||
        moro8asm_parse_ind(instruction, token, out_token) ||
        moro8asm_parse_imm(instruction, token, out_token) ||
        moro8asm_parse_zp(instruction, token, out_token) ||
        moro8asm_parse_implied(instruction, token, out_token))
    {
        return MORO8ASM_TRUE;
    }

    printf("Failed to parse token");

    return MORO8ASM_FALSE;
}

static int moro8asm_assemble_dcb(const struct moro8asm_program* program, const moro8asm_instruction* line, moro8_uword* memory)
{
    if (line->op != MORO8ASM_OP_DCB)
    {
        return MORO8ASM_FALSE;
    }

    moro8_udword i = 0;
    moro8asm_token* token = line->operand;
    while (token->tok == MORO8ASM_TOK_WORD)
    {
        memory[line->offset + i] = token->data.number;

        token = token->next;
        if (!token || token->tok != MORO8ASM_TOK_COMMA)
        {
            break;
        }

        token = token->next;
        ++i;
    }

    return MORO8ASM_TRUE;
}

static int moro8asm_assemble_line(const struct moro8asm_program* program, const moro8asm_instruction* line, moro8_uword* memory)
{
    if (moro8asm_assemble_dcb(program, line, memory))
    {
        return MORO8ASM_TRUE;
    }

    memory[line->offset] = MORO8ASM_OP_MODE[line->op][line->mode];

    if (line->size == 1)
    {
        return MORO8ASM_TRUE;
    }

    moro8_udword value = line->operand->data.number;
    if (line->operand->tok == MORO8ASM_TOK_LABEL)
    {
        moro8asm_instruction* line_ref = moro8asm_program_find_label(program, line->operand->data.label);
        if (!line_ref)
        {
            return MORO8ASM_FALSE;
        }

        value = line_ref->pc;
    }
    if (memory[line->offset] == MORO8_OP_LDA_ABS_X)
    {
        int i = 0;
    }

    // Calculate offset for branchs
    if (MORO8ASM_OP_BRANCH[line->op])
    {
        value = (moro8_uword)(value - (line->pc + line->size));
    }

    memory[line->offset + 1] = (value & 0xFF);

    if (line->size == 3)
    {
        memory[line->offset + 2] = (value & 0xFF00) >> 8;
    }

    return MORO8ASM_TRUE;
}

MORO8ASM_PUBLIC(moro8_udword) moro8asm_assemble(moro8asm_program* program, moro8_uword* buf, moro8_udword size)
{
    memset(buf, 0, size);
    moro8asm_program_unlink(program);

    moro8asm_instruction* line = program->lines;
    while (line)
    {
        moro8asm_assemble_line(program, line, memory);

        line = line->next;
    }

    *out_size = program->size;
    return memory;
}