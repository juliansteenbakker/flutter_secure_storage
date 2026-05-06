cmake_minimum_required(VERSION 3.15)
project(flutter_secure_storage_windows_test LANGUAGES CXX)

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/b514bdc898e2951020cbdca1304b75f5950d1f59.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
# Prevent overriding the parent project's compiler/linker settings on Windows.
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

enable_testing()

# Compile the plugin source directly into the test binary so that the C++
# class symbols are available without requiring DLL exports.
add_executable(flutter_secure_storage_windows_test
  flutter_secure_storage_windows_plugin_test.cpp
  ${CMAKE_CURRENT_SOURCE_DIR}/../flutter_secure_storage_windows_plugin.cpp
)

# The test binary shares the same SECURE_STORAGE_KEY_PREFIX as the plugin so
# that keys written through HandleMethodCall use the same namespace.  A
# dedicated test prefix is used to avoid touching real application data.
target_compile_definitions(flutter_secure_storage_windows_test PRIVATE
  SECURE_STORAGE_KEY_PREFIX="fss_native_test_"
  FLUTTER_PLUGIN_IMPL
)

target_include_directories(flutter_secure_storage_windows_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(flutter_secure_storage_windows_test PRIVATE
  flutter_wrapper_plugin
  GTest::gtest_main
)

target_compile_features(flutter_secure_storage_windows_test PRIVATE cxx_std_17)

# Copy flutter_windows.dll next to the test binary so the process can load it
# both during ctest discovery (PRE_TEST) and during actual test execution.
add_custom_command(TARGET flutter_secure_storage_windows_test POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${FLUTTER_LIBRARY}"
    "$<TARGET_FILE_DIR:flutter_secure_storage_windows_test>"
  COMMENT "Copying flutter_windows.dll for test runner"
)

include(GoogleTest)
# PRE_TEST defers test-case discovery to ctest runtime (not cmake build time),
# so flutter_windows.dll is already present when the binary is first executed.
gtest_discover_tests(flutter_secure_storage_windows_test
  DISCOVERY_MODE PRE_TEST
)
