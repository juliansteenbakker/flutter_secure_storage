#include <flutter/method_result_functions.h>
#include <flutter/standard_method_codec.h>
#include <gtest/gtest.h>
#include <windows.h>

#include <memory>
#include <string>
#include <variant>

#include "flutter_secure_storage_windows_plugin.h"

namespace flutter_secure_storage_windows {
namespace test {

using flutter::EncodableMap;
using flutter::EncodableValue;
using flutter::MethodCall;
using flutter::MethodResultFunctions;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Invoke HandleMethodCall and return true on success, false on error / not-
// implemented.  Optionally captures the success value via |out|.
static bool Invoke(
    FlutterSecureStorageWindowsPlugin& plugin,
    const std::string& method,
    EncodableMap args,
    EncodableValue* out = nullptr) {
  bool succeeded = false;
  plugin.HandleMethodCall(
      MethodCall(method, std::make_unique<EncodableValue>(std::move(args))),
      std::make_unique<MethodResultFunctions<>>(
          [&succeeded, out](const EncodableValue* result) {
            succeeded = true;
            if (out && result) *out = *result;
          },
          /*on_error=*/nullptr,
          /*on_not_implemented=*/nullptr));
  return succeeded;
}

static bool Write(FlutterSecureStorageWindowsPlugin& plugin,
                  const std::string& key, const std::string& value) {
  return Invoke(plugin, "write",
                {{EncodableValue("key"), EncodableValue(key)},
                 {EncodableValue("value"), EncodableValue(value)}});
}

static std::optional<std::string> Read(FlutterSecureStorageWindowsPlugin& plugin,
                                       const std::string& key) {
  EncodableValue out;
  if (!Invoke(plugin, "read", {{EncodableValue("key"), EncodableValue(key)}},
              &out))
    return std::nullopt;
  if (std::holds_alternative<std::string>(out))
    return std::get<std::string>(out);
  return std::nullopt;  // null result == key not present
}

static bool ContainsKey(FlutterSecureStorageWindowsPlugin& plugin,
                        const std::string& key) {
  EncodableValue out;
  Invoke(plugin, "containsKey",
         {{EncodableValue("key"), EncodableValue(key)}}, &out);
  return std::holds_alternative<bool>(out) && std::get<bool>(out);
}

static bool Delete(FlutterSecureStorageWindowsPlugin& plugin,
                   const std::string& key) {
  return Invoke(plugin, "delete",
                {{EncodableValue("key"), EncodableValue(key)}});
}

static bool DeleteAll(FlutterSecureStorageWindowsPlugin& plugin) {
  return Invoke(plugin, "deleteAll", {});
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

class FlutterSecureStorageWindowsPluginTest : public ::testing::Test {
 protected:
  void SetUp() override { DeleteAll(plugin_); }
  void TearDown() override { DeleteAll(plugin_); }

  FlutterSecureStorageWindowsPlugin plugin_;
};

TEST_F(FlutterSecureStorageWindowsPluginTest, WriteAndReadRoundTrip) {
  ASSERT_TRUE(Write(plugin_, "key1", "value1"));
  EXPECT_EQ(Read(plugin_, "key1"), "value1");
}

TEST_F(FlutterSecureStorageWindowsPluginTest, ReadMissingKeyReturnsNullopt) {
  EXPECT_EQ(Read(plugin_, "nonexistent"), std::nullopt);
}

TEST_F(FlutterSecureStorageWindowsPluginTest, OverwriteReturnsNewValue) {
  Write(plugin_, "k", "first");
  Write(plugin_, "k", "second");
  EXPECT_EQ(Read(plugin_, "k"), "second");
}

TEST_F(FlutterSecureStorageWindowsPluginTest, ContainsKeyTrueAfterWrite) {
  Write(plugin_, "k", "v");
  EXPECT_TRUE(ContainsKey(plugin_, "k"));
}

TEST_F(FlutterSecureStorageWindowsPluginTest, ContainsKeyFalseForMissing) {
  EXPECT_FALSE(ContainsKey(plugin_, "nonexistent"));
}

TEST_F(FlutterSecureStorageWindowsPluginTest, DeleteRemovesKey) {
  Write(plugin_, "k", "v");
  ASSERT_TRUE(ContainsKey(plugin_, "k"));
  Delete(plugin_, "k");
  EXPECT_FALSE(ContainsKey(plugin_, "k"));
}

TEST_F(FlutterSecureStorageWindowsPluginTest, DeleteNonexistentIsNoOp) {
  EXPECT_TRUE(Delete(plugin_, "never_written"));
}

TEST_F(FlutterSecureStorageWindowsPluginTest, DeleteAllClearsAllKeys) {
  Write(plugin_, "a", "1");
  Write(plugin_, "b", "2");
  DeleteAll(plugin_);
  EXPECT_FALSE(ContainsKey(plugin_, "a"));
  EXPECT_FALSE(ContainsKey(plugin_, "b"));
}

TEST_F(FlutterSecureStorageWindowsPluginTest, UnknownMethodReturnsNotImplemented) {
  bool not_implemented_called = false;
  plugin_.HandleMethodCall(
      MethodCall("unknownMethod",
                 std::make_unique<EncodableValue>(EncodableMap{})),
      std::make_unique<MethodResultFunctions<>>(
          /*on_success=*/nullptr,
          /*on_error=*/nullptr,
          [&not_implemented_called]() { not_implemented_called = true; }));
  EXPECT_TRUE(not_implemented_called);
}

}  // namespace test
}  // namespace flutter_secure_storage_windows
