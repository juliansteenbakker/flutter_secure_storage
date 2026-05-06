cmake_minimum_required(VERSION 3.15)
set(PROJECT_NAME "flutter_secure_storage_windows")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "flutter_secure_storage_windows_plugin")

add_library(${PLUGIN_NAME} SHARED
  "flutter_secure_storage_windows_plugin.cpp"
)
apply_standard_settings(${PLUGIN_NAME})
set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)
target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_include_directories(${PLUGIN_NAME} INTERFACE
  "${CMAKE_CURRENT_SOURCE_DIR}/include")
target_link_libraries(${PLUGIN_NAME} PRIVATE flutter flutter_wrapper_plugin)

# List of absolute paths to libraries that should be bundled with the plugin
set(flutter_secure_storage_bundled_libraries
  ""
  PARENT_SCOPE
)
if(NOT DEFINED STORAGE_PREFIX)
  add_compile_definitions(SECURE_STORAGE_KEY_PREFIX="${BINARY_NAME}_VGhpcyBpcyB0aGUgcHJlZml4IGZv_")
else()
  add_compile_definitions(SECURE_STORAGE_KEY_PREFIX="${STORAGE_PREFIX}_VGhpcyBpcyB0aGUgcHJlZml4IGZv_")
endif()

if(${include_flutter_secure_storage_windows_tests})
set(TEST_RUNNER "flutter_secure_storage_windows_test")
enable_testing()

include(FetchContent)
FetchContent_Declare(
  googletest
  URL https://github.com/google/googletest/archive/b514bdc898e2951020cbdca1304b75f5950d1f59.zip
  DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
set(INSTALL_GTEST OFF CACHE BOOL "Disable installation of googletest" FORCE)
FetchContent_MakeAvailable(googletest)

add_executable(${TEST_RUNNER}
  "test/flutter_secure_storage_windows_plugin_test.cpp"
  "flutter_secure_storage_windows_plugin.cpp"
)
apply_standard_settings(${TEST_RUNNER})
target_compile_definitions(${TEST_RUNNER} PRIVATE
  SECURE_STORAGE_KEY_PREFIX="fss_native_test_"
  FLUTTER_PLUGIN_IMPL
)
target_include_directories(${TEST_RUNNER} PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
)
target_link_libraries(${TEST_RUNNER} PRIVATE flutter_wrapper_plugin)
target_link_libraries(${TEST_RUNNER} PRIVATE gtest_main)

# flutter_wrapper_plugin has link dependencies on the Flutter DLL.
add_custom_command(TARGET ${TEST_RUNNER} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
    "${FLUTTER_LIBRARY}" $<TARGET_FILE_DIR:${TEST_RUNNER}>
)

include(GoogleTest)
gtest_discover_tests(${TEST_RUNNER})
endif()