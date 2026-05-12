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

  bool deleteKeyring() {
    warmupKeyring();
    return this->storeToKeyring(nlohmann::json::object());
  }

  bool storeToKeyring(nlohmann::json value) {
    const std::string output = value.dump();
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
  // Ensures the default keyring is accessible. Uses the libsecret service API
  // to detect a locked keyring and throw a distinct "KeyringLocked" sentinel so
  // callers can surface the right error code to Dart.
  // Loading all collections also resolves cold-keyring lookup failures:
  // https://gitlab.gnome.org/GNOME/gnome-keyring/-/issues/89
  void warmupKeyring() {
    g_autoptr(GError) err = nullptr;

    SecretService *service = secret_service_get_sync(
        static_cast<SecretServiceFlags>(SECRET_SERVICE_OPEN_SESSION | SECRET_SERVICE_LOAD_COLLECTIONS),
        nullptr, &err);

    if (!service) {
      throw "KeyringLocked";
    }

    SecretCollection *collection = secret_collection_for_alias_sync(
        service, SECRET_COLLECTION_DEFAULT, SECRET_COLLECTION_NONE, nullptr, &err);

    if (!collection) {
      g_object_unref(service);
      throw "KeyringLocked";
    }

    if (!secret_collection_get_locked(collection)) {
      g_object_unref(collection);
      g_object_unref(service);
      return;
    }

    GList *to_unlock = g_list_append(nullptr, collection);
    GList *unlocked_out = nullptr;
    gint n = secret_service_unlock_sync(service, to_unlock, nullptr, &unlocked_out, nullptr);
    g_list_free(to_unlock);
    if (unlocked_out) {
      g_list_free_full(unlocked_out, g_object_unref);
    }
    g_object_unref(collection);
    g_object_unref(service);

    if (n == 0) {
      throw "KeyringLocked";
    }
  }
};
