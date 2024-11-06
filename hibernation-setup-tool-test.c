#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

// Declare the function you want to test
int initialize_tool(int setting);

static void test_initialize_tool(void **state) {
    (void)state;  // Unused in this example
    assert_int_equal(initialize_tool(5), 10);
    assert_int_equal(initialize_tool(0), 0);
}

int main(void) {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_initialize_tool),
    };
    return cmocka_run_group_tests(tests, NULL, NULL);
}
