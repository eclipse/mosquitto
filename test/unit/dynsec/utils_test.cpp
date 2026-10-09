extern "C" {
#include "dynamic_security.h"
}

#include <climits>
#include <gtest/gtest.h>

TEST(EnforcePriorityLimitsTest, PositiveWithinRange) {
  int p = 500;
  enforce_priority_limits(&p);
  EXPECT_EQ(p, 500);
}

TEST(EnforcePriorityLimitsTest, Zero) {
  int p = 0;
  enforce_priority_limits(&p);
  EXPECT_EQ(p, 0);
}

TEST(EnforcePriorityLimitsTest, NegativeWithinRange) {
  int p = -500;
  enforce_priority_limits(&p);
  EXPECT_EQ(p, -500);
}

TEST(EnforcePriorityLimitsTest, ExactMax) {
  int p = PRIORITY_MAX;
  enforce_priority_limits(&p);
  EXPECT_EQ(p, PRIORITY_MAX);
}

TEST(EnforcePriorityLimitsTest, ExactMin) {
  int p = PRIORITY_MIN;
  enforce_priority_limits(&p);
  EXPECT_EQ(p, PRIORITY_MIN);
}

TEST(EnforcePriorityLimitsTest, AboveMax) {
  int p = PRIORITY_MAX + 1;
  enforce_priority_limits(&p);
  EXPECT_EQ(p, PRIORITY_MAX);
}

TEST(EnforcePriorityLimitsTest, BelowMin) {
  int p = PRIORITY_MIN - 1;
  enforce_priority_limits(&p);
  EXPECT_EQ(p, PRIORITY_MIN);
}

TEST(EnforcePriorityLimitsTest, IntMax) {
  int p = INT_MAX;
  enforce_priority_limits(&p);
  EXPECT_EQ(p, PRIORITY_MAX);
}

TEST(EnforcePriorityLimitsTest, IntMin) {
  int p = INT_MIN;
  enforce_priority_limits(&p);
  EXPECT_EQ(p, PRIORITY_MIN);
}

