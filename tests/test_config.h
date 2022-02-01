#pragma once
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <setjmp.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <cmocka.h>
#include "tests/fs_testutils.h"
#include "moro8asm.h"

#define DIRECTORY_DATA "data"
#define DIRECTORY_OUTPUT "output"

typedef enum moro8_opcode moro8_opcode;
typedef enum moro8_register moro8_register;
typedef struct moro8_bus moro8_bus;
typedef struct moro8_registers moro8_registers;
typedef struct moro8_array_memory moro8_array_memory;
typedef struct moro8_vm moro8_vm;

static void moro8_assert_output_dir(char (*buf)[LIBFS_MAX_PATH])
{
	char cwd[LIBFS_MAX_PATH];
	fs_assert_current_dir(&cwd);

	fs_assert_join_path(buf, cwd, DIRECTORY_OUTPUT);

	assert_true(fs_make_dir(buf[0]));
}