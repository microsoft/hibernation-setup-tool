#include <check.h>
#include <stdbool.h> 
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#define access mock_access
#define fopen mock_fopen

int mock_access(const char *pathname, int mode) {
    printf("mock access: pathname = %s, mode = %d\n", pathname, mode);
    if (strcmp(pathname, "/sys/bus/vmbus") == 0 && mode == F_OK) {
        return 0;
    }
    else if (strcmp(pathname, "/dev/snapshot") == 0  && mode == F_OK) {
        return 0;
    }
    return -1;
}

FILE* mock_fopen(const char *filename, const char *mode) {
    printf("mock fopen: filename = %s, mode = %s\n", filename, mode);
    if (strcmp(filename, "/proc/1/cgroup") == 0 && strcmp(mode, "re") == 0) {
        return fmemopen("0::/some/cgroup/path", strlen("0::/some/cgroup/path"), "r");
    }
    else if (strcmp(filename, "/sys/power/disk") == 0 && strcmp(mode, "re") == 0) {
        return fmemopen("platform::/some/cgroup/path", strlen("platform::/some/cgroup/path"), "r");
    }
    //default
    return fopen(filename, mode);
}

bool is_running_in_container(void) {
    printf("Mocking environment\n");
    return false;
}

#include "hibernation-setup-tool.c"

extern bool is_hibernation_enabled_for_vm();
START_TEST(test_is_hibernation_enabled_for_vm) {
    bool result = is_hibernation_enabled_for_vm();
    ck_assert(result);
}
END_TEST

extern bool is_kernel_version_at_least(const char *version);
START_TEST(test_is_kernel_version_at_least) {
    bool result = is_kernel_version_at_least("4.18");
    ck_assert(result);
    result = is_kernel_version_at_least("1.18");
    ck_assert(result);
}
END_TEST

extern bool is_hyperv();
START_TEST(test_is_hyperv) {
    bool result = is_hyperv();
    ck_assert(result);
}
END_TEST

Suite *hibernation_setup_tool_test_suite(void) {
    Suite *s;
    TCase *tc_core;

    s = suite_create("Hibernation");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_is_hyperv);
    tcase_add_test(tc_core, test_is_hibernation_enabled_for_vm);
    tcase_add_test(tc_core, test_is_kernel_version_at_least);
    suite_add_tcase(s, tc_core);
    return s;
}

int main(void) {
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = hibernation_setup_tool_test_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? 0 : 1;
}