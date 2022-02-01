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

MORO8ASM_PUBLIC(moro8_uword*) moro8asm_compile(const char* buf, size_t size, size_t* out_size);

#ifdef __cplusplus
}
#endif

#endif
