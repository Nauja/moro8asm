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
    MORO8ASM_TOK_NUMBER,
    MORO8ASM_TOK_COLON,
    MORO8ASM_TOK_LPAREN,
    MORO8ASM_TOK_RPAREN,
    MORO8ASM_TOK_COMMA,
    MORO8ASM_TOK_HASH,
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
};

struct moro8asm_token;

/** Informations about a single token. */
struct moro8asm_token
{
    /** Token id. */
    moro8asm_tok tok;
    /** Line. */
    size_t line;
    /** Column. */
    size_t col;
    /** Data associated to this token. */
    union
    {
        /** Parsed label .*/
        struct
        {
            /** Buffer. */
            const char* begin;
            /** Size. */
            size_t size;
        } label;
        /** Parsed number. */
        moro8_udword number;
        /** Parsed opcode. */
        moro8asm_op op;
    } data;
    /** Next token. */
    struct moro8asm_token* next;
};

/** Creates a new token. */
MORO8ASM_PUBLIC(struct moro8asm_token*) moro8asm_token_create();

/** Deletes a token. */
MORO8ASM_PUBLIC(void) moro8asm_token_delete(struct moro8asm_token* token);

/**
 * Extracts all the tokens from a program.
 * @param[in] buf Pointer to a buffer
 * @param[in] size Buffer size
 * @return A pointer to the first extracted token.
 */
MORO8ASM_PUBLIC(struct moro8asm_token*) moro8asm_tokenize(const char* buf, size_t size);

MORO8ASM_PUBLIC(moro8_uword*) moro8asm_compile(const char* buf, size_t size, size_t* out_size);

#ifdef __cplusplus
}
#endif

#endif
