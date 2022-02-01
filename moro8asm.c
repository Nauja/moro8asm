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

moro8_uword* moro8asm_compile(const char* buf, size_t size, size_t* out_size)
{

}