cmake_minimum_required(VERSION 3.10)
set(PROJECT_NAME "flutter_secure_storage_linux")
project(${PROJECT_NAME} LANGUAGES CXX)

# This value is used when generating builds using this plugin, so it must
# not be changed
set(PLUGIN_NAME "flutter_secure_storage_linux_plugin")

add_library(${PLUGIN_NAME} SHARED
  "flutter_secure_storage_linux_plugin.cc"
)
apply_standard_settings(${PLUGIN_NAME})
pkg_check_modules(LIBSECRET REQUIRED IMPORTED_TARGET libsecret-1>=0.18.4)

set_target_properties(${PLUGIN_NAME} PROPERTIES
  CXX_VISIBILITY_PRESET hidden)


target_compile_definitions(${PLUGIN_NAME} PRIVATE FLUTTER_PLUGIN_IMPL)
target_include_directories(${PLUGIN_NAME} INTERFACE
"${CMAKE_CURRENT_SOURCE_DIR}/include")
include_directories(${LIBSECRET_INCLUDE_DIRS})

target_link_libraries(${PLUGIN_NAME} PRIVATE flutter)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::GTK)
target_link_libraries(${PLUGIN_NAME} PRIVATE PkgConfig::LIBSECRET)

# List of absolute paths to libraries that should be bundled with the plugin
set(flutter_secure_storage_bundled_libraries
  ""
  PARENT_SCOPE
)
