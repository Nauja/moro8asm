// Here we only test modules
#include <tests/fs_testutils.h>
#include "test_config.h"

#define MORO8ASM_TEST_MODULES_DIR "test_modules"
#define MORO8ASM_TEST_MODULES_INPUT_DIR "test_modules"
#define MORO8ASM_TEST_MODULES_EXPECTED_DIR "test_modules"
#define MORO8ASM_TEST_MODULES_OUTPUT_DIR "test_modules/output"
#define MORO8ASM_NUM_TESTS 150
#define MORO8ASM_PRINT_BUFFER_SIZE 0x10000

typedef struct fs_directory_iterator fs_directory_iterator;
typedef struct CMUnitTest CMUnitTest;

typedef struct test_state
{
    char input[LIBFS_MAX_PATH];
    char expected[LIBFS_MAX_PATH];
    char output[LIBFS_MAX_PATH];
    moro8asm_module *module;
} test_state;

/**
 * Run a test from test_opcodes directory.
 * @param[in] state Initial state
 */
void test_func(void **initial_state)
{
    const test_state *state = (const test_state *)*initial_state;
    moro8asm_module *module = state->module;

    // Print output state
    char output[MORO8ASM_PRINT_BUFFER_SIZE];
    moro8asm_module_print(module, output, MORO8ASM_PRINT_BUFFER_SIZE);
    fs_assert_write_file(state->output, output, MORO8ASM_PRINT_BUFFER_SIZE - 1);

    // Compare with initial state
    size_t size = 0;
    const char *expected = (const char *)fs_assert_read_file(state->expected, &size);
    assert_string_equal(output, expected);
}

int setup(void **initial_state)
{
    test_state *state = (test_state *)*initial_state;

    // Read test
    size_t size = 0;
    void *buf = NULL;
    buf = fs_assert_read_file(state->input, &size);

    // Parse test
    state->module = moro8asm_module_create();
    assert_non_null(state->module);
    moro8asm_module_parse(state->module, buf, size);

    return 0;
}

int teardown(void **initial_state)
{
    test_state *state = (test_state *)*initial_state;

    // Delete module
    moro8asm_module_delete(state->module);
    free(state);

    return 0;
}

int main(void)
{
    CMUnitTest tests[MORO8ASM_NUM_TESTS];
    memset(tests, 0, sizeof(CMUnitTest) * MORO8ASM_NUM_TESTS);

    // Current working directory
    char cwd[LIBFS_MAX_PATH];
    fs_assert_current_dir(&cwd);

    // Get test_opcodes directory
    char input_dir[LIBFS_MAX_PATH];
    char expected_dir[LIBFS_MAX_PATH];
    char output_dir[LIBFS_MAX_PATH];
    fs_assert_join_path(&input_dir, cwd, MORO8ASM_TEST_MODULES_INPUT_DIR);
    fs_assert_join_path(&expected_dir, cwd, MORO8ASM_TEST_MODULES_EXPECTED_DIR);
    fs_assert_join_path(&output_dir, cwd, MORO8ASM_TEST_MODULES_OUTPUT_DIR);
    fs_assert_make_dir(output_dir);

    // Iterate directory
    fs_directory_iterator *it = fs_assert_open_dir(input_dir);

    struct CMUnitTest *test = NULL;
    size_t test_index = 0;

    // Load all tests
    while (fs_read_dir(it))
    {
        if (!fs_string_ends_with(it->path, ".s"))
        {
            continue;
        }

        // Setup initial state
        test_state *state = (test_state *)malloc(sizeof(test_state));
        fs_assert_join_path(&state->input, input_dir, it->path);
        fs_assert_join_path(&state->expected, expected_dir, it->path);
        fs_assert_join_path(&state->output, output_dir, it->path);

        // Setup test
        test = &tests[test_index];
        test->name = (char *)malloc(strlen(it->path));
        strcpy((char *)test->name, it->path);
        test->test_func = test_func;
        test->initial_state = (void *)state;
        test->setup_func = setup;
        test->teardown_func = teardown;

        ++test_index;
    }

    fs_close_dir(it);

    return cmocka_run_group_tests(tests, NULL, NULL);
}

#undef MORO8_NUM_TESTS