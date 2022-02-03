#include <tests/fs_testutils.h>
#include "test_config.h"

#define MORO8ASM_TEST_PROGRAMS_INPUT_DIR "test_programs"
#define MORO8ASM_TEST_PROGRAMS_EXPECTED_DIR "test_programs/expected"
#define MORO8ASM_TEST_PROGRAMS_OUTPUT_DIR "test_programs/output"
#define MORO8ASM_NUM_TESTS 10

typedef struct fs_directory_iterator fs_directory_iterator;
typedef struct CMUnitTest CMUnitTest;

typedef struct test_state
{
    char input[LIBFS_MAX_PATH];
    char expected[LIBFS_MAX_PATH];
    char output[LIBFS_MAX_PATH];
} test_state;

/**
 * Run a test from test_opcodes directory.
 * @param[in] state Initial state
 */
void test_func(void** initial_state) {
    const test_state* state = (const test_state*)*initial_state;

    // Read program
    size_t buf_size = 0;
    void* buf = NULL;
    buf = fs_assert_read_file(state->input, &buf_size);

    // Compile
    size_t out_size = 0;
    moro8_uword* out = moro8asm_compile((const char*)buf, buf_size, &out_size);

    // Import into first vm
    moro8_vm vm1;
    moro8_init(&vm1);

    moro8_array_memory memory1;
    moro8_array_memory_init(&memory1);
    vm1.memory = (moro8_bus*)&memory1;

    moro8_set_memory(&vm1, out, 0x600, out_size);

    // Dump vm state
    char dump[MORO8_PRINT_BUFFER_SIZE];
    moro8_print(&vm1, dump, MORO8_PRINT_BUFFER_SIZE);

    // Print output state
    fs_assert_write_file(state->output, (void*)dump, MORO8_PRINT_BUFFER_SIZE - 1);

    // Compare expected state
    const char* expected = (const char*)fs_assert_read_file(state->expected, &buf_size);

    moro8_vm vm2;
    moro8_init(&vm2);

    moro8_array_memory memory2;
    moro8_array_memory_init(&memory2);
    vm2.memory = (moro8_bus*)&memory2;

    moro8_parse(&vm2, expected, buf_size);
    assert_true(moro8_equal(&vm1, &vm2));
}

int main(void) {
    CMUnitTest tests[MORO8ASM_NUM_TESTS];
    memset(tests, 0, sizeof(CMUnitTest) * MORO8ASM_NUM_TESTS);

    // Current working directory
    char cwd[LIBFS_MAX_PATH];
    fs_assert_current_dir(&cwd);

    // Get test_opcodes directory
    char input_dir[LIBFS_MAX_PATH];
    char expected_dir[LIBFS_MAX_PATH];
    char output_dir[LIBFS_MAX_PATH];
    fs_assert_join_path(&input_dir, cwd, MORO8ASM_TEST_PROGRAMS_INPUT_DIR);
    fs_assert_join_path(&expected_dir, cwd, MORO8ASM_TEST_PROGRAMS_EXPECTED_DIR);
    fs_assert_join_path(&output_dir, cwd, MORO8ASM_TEST_PROGRAMS_OUTPUT_DIR);
    fs_assert_make_dir(output_dir);

    // Iterate directory
    fs_directory_iterator* it = fs_assert_open_dir(input_dir);

    struct CMUnitTest* test = NULL;
    size_t test_index = 0;

    // Load all tests
    while (fs_read_dir(it))
    {
        if (!fs_string_ends_with(it->path, ".asm"))
        {
            continue;
        }

        // Setup initial state
        test_state* state = (test_state*)malloc(sizeof(test_state));
        fs_assert_join_path(&state->input, input_dir, it->path);
        fs_assert_join_path(&state->expected, expected_dir, it->path);
        fs_assert_join_path(&state->output, output_dir, it->path);

        // Setup test
        test = &tests[test_index];
        test->name = (char*)malloc(strlen(it->path));
        strcpy((char*)test->name, it->path);
        test->test_func = test_func;
        test->initial_state = (void*)state;

        ++test_index;
    }

    fs_close_dir(it);

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#undef MORO8ASM_NUM_TESTS