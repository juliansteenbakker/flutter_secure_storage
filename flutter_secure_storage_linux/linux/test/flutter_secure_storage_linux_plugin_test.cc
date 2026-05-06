#include <gtest/gtest.h>
#include <memory>

#include "include/Secret.hpp"

namespace flutter_secure_storage_linux {
namespace test {

class SecretStorageTest : public ::testing::Test {
 protected:
  void SetUp() override {
    storage_ = std::make_unique<SecretStorage>("fss_native_test");
    storage_->addAttribute("account", "fss_native_test.secureStorage");
    storage_->deleteKeyring();
  }

  void TearDown() override { storage_->deleteKeyring(); }

  std::unique_ptr<SecretStorage> storage_;
};

TEST_F(SecretStorageTest, WriteAndReadRoundTrip) {
  ASSERT_TRUE(storage_->addItem("key1", "value1"));
  EXPECT_EQ(storage_->getItem("key1"), "value1");
}

TEST_F(SecretStorageTest, ReadMissingKeyReturnsEmpty) {
  EXPECT_EQ(storage_->getItem("nonexistent"), "");
}

TEST_F(SecretStorageTest, OverwriteReturnsNewValue) {
  storage_->addItem("k", "first");
  storage_->addItem("k", "second");
  EXPECT_EQ(storage_->getItem("k"), "second");
}

TEST_F(SecretStorageTest, ContainsKeyTrueAfterWrite) {
  storage_->addItem("k", "v");
  nlohmann::json data = storage_->readFromKeyring();
  EXPECT_TRUE(data.contains("k"));
}

TEST_F(SecretStorageTest, ContainsKeyFalseForMissing) {
  nlohmann::json data = storage_->readFromKeyring();
  EXPECT_FALSE(data.contains("nonexistent"));
}

TEST_F(SecretStorageTest, DeleteRemovesKey) {
  storage_->addItem("k", "v");
  storage_->deleteItem("k");
  EXPECT_EQ(storage_->getItem("k"), "");
  nlohmann::json data = storage_->readFromKeyring();
  EXPECT_FALSE(data.contains("k"));
}

TEST_F(SecretStorageTest, DeleteNonexistentIsNoOp) {
  EXPECT_NO_THROW(storage_->deleteItem("never_written"));
}

TEST_F(SecretStorageTest, DeleteAllClearsStorage) {
  storage_->addItem("a", "1");
  storage_->addItem("b", "2");
  storage_->deleteKeyring();
  EXPECT_EQ(storage_->getItem("a"), "");
  EXPECT_EQ(storage_->getItem("b"), "");
}

TEST_F(SecretStorageTest, ReadAllReturnsAllEntries) {
  storage_->addItem("k1", "v1");
  storage_->addItem("k2", "v2");
  nlohmann::json data = storage_->readFromKeyring();
  EXPECT_EQ(data["k1"], "v1");
  EXPECT_EQ(data["k2"], "v2");
}

}  // namespace test
}  // namespace flutter_secure_storage_linux
