#pragma once

/**
 * @file test_paths.h
 * @brief Scratch file/directory names that are private to the running test case.
 *
 * ctest (via gtest_discover_tests) runs every test case as its OWN process, and
 * all of those processes share one working directory — the build tree. A fixed
 * scratch name is therefore shared mutable state between cases, and `ctest -j`
 * cheerfully runs two of them at the same moment: one case's SetUp/TearDown wipes
 * the file another case is still writing, which shows up as a rare, unreproducible
 * failure in whichever of the two lost the race.
 *
 * Deriving the name from the case that is running removes the sharing. It stays
 * deterministic on purpose — unlike a pid or random suffix, a leftover from a
 * crashed run is reclaimed by the next run of the same test instead of piling up.
 */

#include <gtest/gtest.h>

#include <cctype>
#include <string>

namespace librats_test {

/// "<Suite>_<Case>" for the currently running test, sanitized to a filename-safe
/// token (TEST_P names carry '/' and parameter text). Falls back to "unknown"
/// when called outside a running test.
inline std::string current_test_tag() {
    const auto* info = ::testing::UnitTest::GetInstance()->current_test_info();
    if (!info) return "unknown";
    std::string tag = std::string(info->test_suite_name()) + "_" + info->name();
    for (char& c : tag)
        if (!std::isalnum(static_cast<unsigned char>(c)) && c != '_') c = '_';
    return tag;
}

/// `prefix` made private to the running case: "<prefix>_<Suite>_<Case>".
inline std::string scratch_name(const std::string& prefix) {
    return prefix + "_" + current_test_tag();
}

} // namespace librats_test
