#include "FHashTable.hpp"
#include "json.hpp"
#include <libsecret/secret.h>
#include <memory>

#define secret_autofree _GLIB_CLEANUP(secret_cleanup_free)
static inline void secret_cleanup_free(gchar **p) { secret_password_free(*p); }

class SecretStorage {
  FHashTable m_attributes;
  std::string label;
  SecretSchema the_schema;

public:
  const char *getLabel() { return label.c_str(); }
  void setLabel(const char *label) { this->label = label; }

  SecretStorage(const char *_label = "default") : label(_label) {
    the_schema = {label.c_str(),
                  SECRET_SCHEMA_NONE,
                  {
                      {"account", SECRET_SCHEMA_ATTRIBUTE_STRING},
                  }};
  }

  void addAttribute(const char *key, const char *value) {
    m_attributes.insert(key, value);
  }

  bool addItem(const char *key, const char *value) {
    nlohmann::json root = readFromKeyring();
    root[key] = value;
    return storeToKeyring(root);
  }

  std::string getItem(const char *key) {
    std::string result;
    nlohmann::json root = readFromKeyring();
    nlohmann::json value = root[key];
    if(value.is_string()){
      result = value.get<std::string>();
      return result;
    }
    return "";
  }

  void deleteItem(const char *key) {
    try {
      nlohmann::json root = readFromKeyring();
      if (root.is_null()) {
          return;
      }
      root.erase(key);
      storeToKeyring(root);
    } catch (const std::exception& e) {
        return;
    }
  }

  bool deleteKeyring() { return this->storeToKeyring(nlohmann::json()); }

  bool storeToKeyring(nlohmann::json value) {
    const std::string output = value.dump(0);
    g_autoptr(GError) err = nullptr;
    bool result = secret_password_storev_sync(
        &the_schema, m_attributes.getGHashTable(), nullptr, label.c_str(),
        output.c_str(), nullptr, &err);

    if (err) {
      throw err->message;
    }

    return result;
  }

  nlohmann::json readFromKeyring() {
    nlohmann::json value;
    g_autoptr(GError) err = nullptr;

    warmupKeyring();

    secret_autofree gchar *result = secret_password_lookupv_sync(
        &the_schema, m_attributes.getGHashTable(), nullptr, &err);

    if (err) {
      throw err->message;
    }
    if(result != NULL && strcmp(result, "") != 0){
      value = nlohmann::json::parse(result);
    }
    return value;
  }

private:
  // Search with schemas fails in cold keyrings.
  // https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/89
  //
  // Note that we're not using the workaround mentioned in the above issue. Instead, we're using
  // a workaround as implemented in http://crbug.com/660005. Reason being that with the lookup
  // approach we can't distinguish whether the keyring was actually unlocked or whether the user
  // cancelled the password prompt.
  void warmupKeyring() {
    g_autoptr(GError) err = nullptr;

    FHashTable attributes;
    attributes.insert("explanation", "Because of quirks in the gnome libsecret API, "
            "flutter_secret_storage needs to store a dummy entry to guarantee that "
            "this keyring was properly unlocked. More details at http://crbug.com/660005.");

    const gchar* dummy_label = "FlutterSecureStorage Control";

    // Store a dummy entry without `the_schema`.
    bool success = secret_password_storev_sync(
        NULL, attributes.getGHashTable(), nullptr, dummy_label,
        "The meaning of life", nullptr, &err);

    if (!success) {
      throw "Failed to unlock the keyring";
    }
  }
};
