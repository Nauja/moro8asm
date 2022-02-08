#ifndef MORO8ASM__h
#define MORO8ASM__h

#ifdef __cplusplus
extern "C"
{
#endif

#include "moro8.h"

/** Major version of moro8asm. */
#define MORO8ASM_VERSION_MAJOR 0
/** Minor version of moro8asm. */
#define MORO8ASM_VERSION_MINOR 0
/** Patch version of moro8asm. */
#define MORO8ASM_VERSION_PATCH 1

/* Define to 1 if you have the <stdio.h> header file. */
#ifndef HAVE_STDIO_H
#define HAVE_STDIO_H 1
#endif

/* Define to 1 if you have the <stdlib.h> header file. */
#ifndef HAVE_STDLIB_H
#define HAVE_STDLIB_H 1
#endif

/* Define to 1 if you have the <string.h> header file. */
#ifndef HAVE_STRING_H
#define HAVE_STRING_H 1
#endif

/* Define to 1 if you have the `free' function. */
#ifndef HAVE_FREE
#define HAVE_FREE 1
#endif

/* Define to 1 if you have the `malloc' function. */
#ifndef HAVE_MALLOC
#define HAVE_MALLOC 1
#endif

/* Define to 1 if you build with Doxygen. */
#ifndef MORO8ASM_DOXYGEN
/* #undef MORO8ASM_DOXYGEN */
#endif

#ifndef MORO8ASM_MALLOC
#ifdef HAVE_MALLOC
/**
 * Defines the malloc function used by moro8asm at compile time.
 *
 * @code
 * void* my_malloc(size_t size)
 * {
 *     // do something
 * }
 * 
 * #define MORO8ASM_MALLOC my_malloc
 * @endcode
 */
#define MORO8ASM_MALLOC malloc
#else
#define MORO8ASM_MALLOC(size) NULL
#endif
#endif

#ifndef MORO8ASM_FREE
#ifdef HAVE_FREE
/**
* Defines the free function used by moro8asm at compile time.
*
* @code 
* void my_free(void* ptr)
* {
*     // do something
* }
* 
* #define MORO8ASM_FREE my_free
* @endcode
*/
#define MORO8ASM_FREE free
#else
#define MORO8ASM_FREE(ptr)
#endif
#endif

#if !defined(__WINDOWS__) && (defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32))
#define __WINDOWS__
#endif

#ifdef __WINDOWS__
#define MORO8ASM_CDECL __cdecl
#define MORO8ASM_STDCALL __stdcall

/* export symbols by default, this is necessary for copy pasting the C and header file */
#if !defined(MORO8ASM_HIDE_SYMBOLS) && !defined(MORO8ASM_IMPORT_SYMBOLS) && !defined(MORO8ASM_EXPORT_SYMBOLS)
#define MORO8ASM_EXPORT_SYMBOLS
#endif

#if defined(MORO8ASM_HIDE_SYMBOLS)
#define MORO8ASM_PUBLIC(type)   type MORO8ASM_STDCALL
#elif defined(MORO8ASM_EXPORT_SYMBOLS)
#define MORO8ASM_PUBLIC(type)   __declspec(dllexport) type MORO8ASM_STDCALL
#elif defined(MORO8ASM_IMPORT_SYMBOLS)
#define MORO8ASM_PUBLIC(type)   __declspec(dllimport) type MORO8ASM_STDCALL
#endif
#else /* !__WINDOWS__ */
#define MORO8ASM_CDECL
#define MORO8ASM_STDCALL

#if (defined(__GNUC__) || defined(__SUNPRO_CC) || defined (__SUNPRO_C)) && defined(CJSON_API_VISIBILITY)
#define MORO8ASM_PUBLIC(type)   __attribute__((visibility("default"))) type
#else
#define MORO8ASM_PUBLIC(type) type
#endif
#endif

/** Struct for custom hooks configuration. */
struct moro8asm_hooks {
	/** Custom malloc function. */
    void *(*malloc_fn)(size_t size);
	/** Custom free function. */
    void (*free_fn)(void *ptr);
};

/**
 * Register custom hooks.
 *
 * @code
 * struct moro8asm_hooks hooks = { malloc, free };
 * moro8asm_init_hooks(&hooks);
 * @endcode
 * @param[in] hooks Hooks configuration
 */
MORO8ASM_PUBLIC(void) moro8asm_init_hooks(struct moro8asm_hooks *hooks);

/** Enum for parser tokens. */
enum moro8asm_tok
{
    MORO8ASM_TOK_END,
    MORO8ASM_TOK_LABEL,
    MORO8ASM_TOK_OPCODE,
    MORO8ASM_TOK_WORD,
    MORO8ASM_TOK_DWORD,
    MORO8ASM_TOK_X,
    MORO8ASM_TOK_Y,
    MORO8ASM_TOK_COLON,
    MORO8ASM_TOK_LPAREN,
    MORO8ASM_TOK_RPAREN,
    MORO8ASM_TOK_COMMA,
    MORO8ASM_TOK_HASH,
    MORO8ASM_TOK_STAR,
    MORO8ASM_TOK_EQUAL,
};

/** Enum for opcodes. */
enum moro8asm_op
{
    MORO8ASM_OP_ADC,
    MORO8ASM_OP_AND,
    MORO8ASM_OP_ASL,
    MORO8ASM_OP_BCC,
    MORO8ASM_OP_BCS,
    MORO8ASM_OP_BEQ,
    MORO8ASM_OP_BIT,
    MORO8ASM_OP_BMI,
    MORO8ASM_OP_BNE,
    MORO8ASM_OP_BPL,
    MORO8ASM_OP_BVC,
    MORO8ASM_OP_BVS,
    MORO8ASM_OP_CLC,
    MORO8ASM_OP_CLV,
    MORO8ASM_OP_CMP,
    MORO8ASM_OP_CPX,
    MORO8ASM_OP_CPY,
    MORO8ASM_OP_DEA,
    MORO8ASM_OP_DEC,
    MORO8ASM_OP_DEX,
    MORO8ASM_OP_DEY,
    MORO8ASM_OP_EOR,
    MORO8ASM_OP_INA,
    MORO8ASM_OP_INC,
    MORO8ASM_OP_INX,
    MORO8ASM_OP_INY,
    MORO8ASM_OP_JMP,
    MORO8ASM_OP_JSR,
    MORO8ASM_OP_LDA,
    MORO8ASM_OP_LDX,
    MORO8ASM_OP_LDY,
    MORO8ASM_OP_LSR,
    MORO8ASM_OP_NOP,
    MORO8ASM_OP_ORA,
    MORO8ASM_OP_PHA,
    MORO8ASM_OP_PHP,
    MORO8ASM_OP_PLA,
    MORO8ASM_OP_PLP,
    MORO8ASM_OP_ROL,
    MORO8ASM_OP_ROR,
    MORO8ASM_OP_RTS,
    MORO8ASM_OP_SBC,
    MORO8ASM_OP_SEC,
    MORO8ASM_OP_STA,
    MORO8ASM_OP_STX,
    MORO8ASM_OP_STY,
    MORO8ASM_OP_TAX,
    MORO8ASM_OP_TAY,
    MORO8ASM_OP_TSX,
    MORO8ASM_OP_TXA,
    MORO8ASM_OP_TYA,
    MORO8ASM_OP_DCB,
    MORO8ASM_OP_MAX,
};

/** Enum for addressing modes. */
enum moro8asm_addr
{
    /** LDA $06d3 */
    MORO8ASM_ADDR_ABS,
    /** LDA $8000,x */
    MORO8ASM_ADDR_ABS_X,
    /** LDA $8000,y */
    MORO8ASM_ADDR_ABS_Y,
    /** LDA #$05 */
    MORO8ASM_ADDR_IMM,
    /** CLC */
    MORO8ASM_ADDR_IMPLIED,
    /** JMP ($9000) */
    MORO8ASM_ADDR_IND,
    /** LDA ($05,x) */
    MORO8ASM_ADDR_IND_X,
    /** LDA ($10),y */
    MORO8ASM_ADDR_IND_Y,
    /** LDX $13 */
    MORO8ASM_ADDR_ZP,
    /** LDA $00,x */
    MORO8ASM_ADDR_ZP_X,
    /** LDA $00,y */
    MORO8ASM_ADDR_ZP_Y,
    MORO8ASM_ADDR_MAX
};

struct moro8asm_token;

/** Informations about a single token. */
struct moro8asm_token
{
    /** Token id. */
    enum moro8asm_tok tok;
    /** Line. */
    size_t line;
    /** Column. */
    size_t col;
    /** Data associated to this token. */
    union
    {
        /** Parsed label .*/
        const char* label;
        /** Parsed number. */
        moro8_udword number;
        /** Parsed opcode. */
        enum moro8asm_op op;
    } data;
    /** Next token. */
    struct moro8asm_token* next;
};

/** Creates a new token. */
MORO8ASM_PUBLIC(struct moro8asm_token*) moro8asm_token_create();

/** Deletes a token. */
MORO8ASM_PUBLIC(void) moro8asm_token_delete(struct moro8asm_token* token);

struct moro8asm_instruction;

/** Informations about a single instruction. */
struct moro8asm_instruction
{
    /** Absolute memory address. */
    moro8_udword pc;
    /** Relative memory address. */
    moro8_udword offset;
    /** Line. */
    size_t line;
    /** Label on this line. */
    const char* label;
    /** Opcode. */
    enum moro8asm_op op;
    /** Addressing mode. */
    enum moro8asm_addr mode;
    /** The size of this instruction. */
    moro8_uword size;
    /** Operand. */
    struct moro8asm_token* operand;
    /** Next instruction. */
    struct moro8asm_instruction* next;
};

/** Creates a new instruction. */
MORO8ASM_PUBLIC(struct moro8asm_instruction*) moro8asm_instruction_create();

/** Deletes an instruction. */
MORO8ASM_PUBLIC(void) moro8asm_instruction_delete(struct moro8asm_instruction* instruction);

/**
 * Gets the address of an instruction.
 * @param[in] instruction Some instruction
 * @return Address.
 */
MORO8ASM_PUBLIC(moro8_udword) moro8asm_instruction_get_pc(const struct moro8asm_instruction* instruction);

/**
 * Gets the line of an instruction.
 * @param[in] instruction Some instruction
 * @return Line number.
 */
MORO8ASM_PUBLIC(size_t) moro8asm_instruction_get_line(const struct moro8asm_instruction* instruction);

/**
 * Gets the size of an instruction.
 * @param[in] instruction Some instruction
 * @return Size.
 */
MORO8ASM_PUBLIC(moro8_uword) moro8asm_instruction_get_size(const struct moro8asm_instruction* instruction);

/**
 * Gets the next instruction.
 * @param[in] instruction Some instruction
 * @return Pointer to the next instruction or NULL.
 */
MORO8ASM_PUBLIC(struct moro8asm_instruction*) moro8asm_instruction_get_next(const struct moro8asm_instruction* instruction);

struct moro8asm_label_ref;

/** Stores a reference to a label. */
struct moro8asm_label_ref
{
    /** Label reference. */
    const char* label;
    /** Corresponding instruction. */
    struct moro8asm_instruction* instruction;
    /** Next label. */
    struct moro8asm_label_ref* next;
};

/** Creates a new label reference. */
MORO8ASM_PUBLIC(struct moro8asm_label_ref*) moro8asm_label_ref_create();

/** Deletes a label reference. */
MORO8ASM_PUBLIC(void) moro8asm_label_ref_delete(struct moro8asm_label_ref* ref);

/** Informations about compiled program. */
struct moro8asm_program
{
    /** Mapping between labels and instructions. */
    struct moro8asm_label_ref* labels;
    /** Number of labels. */
    size_t num_labels;
    /** First instruction. */
    struct moro8asm_instruction* lines;
    /** Number of lines. */
    size_t num_lines;
    /** Size of the program in bytes. */
    moro8_udword size;
};

/** Creates a new program. */
MORO8ASM_PUBLIC(struct moro8asm_program*) moro8asm_program_create();

/** Deletes a program. */
MORO8ASM_PUBLIC(void) moro8asm_program_delete(struct moro8asm_program* program);

/**
 * Adds a label to the program.
 * @param[in] program Program
 * @param[in] label Some null-terminated string
 * @param[in] line Line the label is found at
 */
MORO8ASM_PUBLIC(void) moro8asm_program_add_label(struct moro8asm_program* program, const char* label, struct moro8asm_instruction* line);

/**
 * Finds an existing label.
 * @param[in] program Program
 * @param[in] label Some null-terminated string
 * @return Line the label is found at.
 */
MORO8ASM_PUBLIC(struct moro8asm_instruction*) moro8asm_program_find_label(struct moro8asm_program* program, const char* label);

/**
 * Gets a label of the program.
 * @param[in] program Program
 * @param[in] index Label number
 * @return Pointer to the label or NULL.
 */
MORO8ASM_PUBLIC(struct moro8asm_label_ref*) moro8asm_program_get_label(const struct moro8asm_program* program, size_t index);

/**
 * Gets the number of labels.
 * @param[in] program Program
 * @return Number of labels.
 */
MORO8ASM_PUBLIC(size_t) moro8asm_program_num_labels(const struct moro8asm_program* program);

/**
 * Gets a line of the program.
 * @param[in] program Program
 * @param[in] index Line number
 * @return Pointer to the line or NULL.
 */
MORO8ASM_PUBLIC(struct moro8asm_instruction*) moro8asm_program_get_line(const struct moro8asm_program* program, size_t index);

/**
 * Gets the number of lines.
 * @param[in] program Program
 * @return Number of lines.
 */
MORO8ASM_PUBLIC(size_t) moro8asm_program_num_lines(const struct moro8asm_program* program);

/**
 * Gets the number of bytes in the program.
 * @param[in] program Program
 * @return Number of bytes.
 */
MORO8ASM_PUBLIC(moro8_udword) moro8asm_program_size(const struct moro8asm_program* program);

/**
 * First step: Extracts tokens from the textual representation of a program.
 * @param[in] buf Pointer to a buffer
 * @param[in] size Buffer size
 * @return A pointer to the first token.
 */
MORO8ASM_PUBLIC(struct moro8asm_token*) moro8asm_tokenize(const char* buf, size_t size);

/**
 * Second step: Parses from tokens to program.
 * @param[in] token Pointer to a list of tokens
 * @return Parsed program.
 */
MORO8ASM_PUBLIC(struct moro8asm_program*) moro8asm_parse(const struct moro8asm_token* token);

/**
 * Third step: Assembles a program.
 * @param[in] program Pointer to a program
 * @param[out] out_size Number of bytes written
 * @return Program bytes.
 */
MORO8ASM_PUBLIC(moro8_uword*) moro8asm_assemble(const struct moro8asm_program* program, size_t* out_size);

/**
 * Compiles the textual representation of a program to bytes.
 * @param[in] buf Pointer to a buffer
 * @param[in] size Buffer size
 * @param[out] Number of bytes written
 * @return Program bytes.
 */
MORO8ASM_PUBLIC(moro8_uword*) moro8asm_compile(const char* buf, size_t size, size_t* out_size);

#ifdef __cplusplus
}
#endif

#endif
