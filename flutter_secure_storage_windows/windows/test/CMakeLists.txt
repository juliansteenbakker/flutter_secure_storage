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

add_executable(flutter_secure_storage_windows_test
  flutter_secure_storage_windows_plugin_test.cpp
)

# The test binary shares the same SECURE_STORAGE_KEY_PREFIX as the plugin so
# that keys written through HandleMethodCall use the same namespace.  A
# dedicated test prefix is used to avoid touching real application data.
target_compile_definitions(flutter_secure_storage_windows_test PRIVATE
  SECURE_STORAGE_KEY_PREFIX="fss_native_test_"
)

target_include_directories(flutter_secure_storage_windows_test PRIVATE
  ${CMAKE_CURRENT_SOURCE_DIR}/..
)

target_link_libraries(flutter_secure_storage_windows_test PRIVATE
  ${PLUGIN_NAME}
  GTest::gtest_main
)

target_compile_features(flutter_secure_storage_windows_test PRIVATE cxx_std_17)

include(GoogleTest)
gtest_discover_tests(flutter_secure_storage_windows_test)
