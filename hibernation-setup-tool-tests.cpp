#include "gtest/gtest.h"

// We use extern to prevent name-mangling
// https://www.geeksforgeeks.org/extern-c-in-c/
extern "C" {
#include "hibernation-setup-tool.c"
}


class HSTTest : public testing::Test {
 protected:
  // Per-test-suite set-up.
  // Called before the first test in this test suite.
  // Can be omitted if not needed.
  static void SetUpTestSuite() {
    // Avoid reallocating static objects if called in subclasses of HSTTest.
    if (shared_resource_ == nullptr) {
      shared_resource_ = new ...;
    }
  }

  // Per-test-suite tear-down.
  // Called after the last test in this test suite.
  // Can be omitted if not needed.
  static void TearDownTestSuite() {
    delete shared_resource_;
    shared_resource_ = nullptr;
  }

  // You can define per-test set-up logic as usual.
  void SetUp() override { ... }

  // You can define per-test tear-down logic as usual.
  void TearDown() override { ... }

  // Some expensive resource shared by all tests.
  static T* shared_resource_;
  // Other resources for example:
  static char *usr_sbin = "/usr/sbin";
  static char *systemd_dir = "/lib/systemd/system";


};

T* HSTTest::shared_resource_ = nullptr;


// Ideas for tests: 

// Test without a test fixture (so no setup/teardown called)
TEST(access, essential_files){
    EXPECT_NE(fopen("/proc/1/cgroup", "re"), nullptr);
    EXPECT_EQ(access("/dev/snapshot", F_OK), 0);
}

TEST_F(HSTTest, test_services_enabled) {
    // ... you can refer to shared_resource_ here ...
    spawn_and_wait("systemctl", 2, "disable", "hibernate.service");
    spawn_and_wait("systemctl", 2, "disable", "resume.service");
    spawn_and_wait("systemctl", 2, "disable", "hibernation-setup-tool.service");

    link_and_enable_systemd_service(...)

    // Check if the services in the right folder and enabled
    // EXPECT_EQ

}

TEST_F(HSTTest, check_physical_memory) {
  // ... you can refer to shared_resource_ here ...
  // Check if physical memory function is correct
  // Provide dummy file for test to read from 
}


TEST_F(HSTTest, check_swap_needed_size) {
    // ... you can refer to shared_resource_ here ...
    EXPECT_EQ(swap_needed_size(2 * GIGA_BYTES), 2 * GIGA_BYTES * 3); 
    EXPECT_EQ(swap_needed_size(8 * GIGA_BYTES), 8 * GIGA_BYTES * 2); 
    EXPECT_EQ(swap_needed_size(64 * GIGA_BYTES), (64 * GIGA_BYTES * 3) / 2); 
    EXPECT_EQ(swap_needed_size(256 * GIGA_BYTES), (256 * GIGA_BYTES * 5) / 4); 

    // Expect this to throw a log_fatal
    EXPECT_EQ(swap_needed_size(256 * GIGA_BYTES + 1), ...log_fatal...); 
}



