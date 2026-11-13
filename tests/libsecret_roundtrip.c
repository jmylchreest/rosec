#include <libsecret/secret.h>
#include <string.h>
static const SecretSchema schema = {
 .name = "org.rosec.InteropTest", .flags = SECRET_SCHEMA_NONE,
 .attributes = {{ "test-id", SECRET_SCHEMA_ATTRIBUTE_STRING }, { NULL, 0 }}
};
int main(void) {
 GError *error = NULL;
 const char *values[] = {"first-fixture-secret", "replacement-fixture-secret"};
 for (unsigned i = 0; i < 2; i++) {
  if (!secret_password_store_sync(&schema, SECRET_COLLECTION_DEFAULT, "Interop fixture", values[i], NULL, &error, "test-id", "isolated-roundtrip", NULL)) goto fail;
  char *got = secret_password_lookup_sync(&schema, NULL, &error, "test-id", "isolated-roundtrip", NULL);
  if (error || !got || strcmp(got, values[i])) { secret_password_free(got); goto fail; }
  secret_password_free(got);
 }
 if (!secret_password_clear_sync(&schema, NULL, &error, "test-id", "isolated-roundtrip", NULL)) goto fail;
 char *got = secret_password_lookup_sync(&schema, NULL, &error, "test-id", "isolated-roundtrip", NULL);
 if (error || got) { secret_password_free(got); goto fail; }
 const char binary[] = {0, (char)255, (char)128, 0};
 const char *mime = "application/octet-stream; fixture=exact";
 SecretValue *value = secret_value_new(binary, sizeof binary, mime);
 gboolean stored = secret_password_store_binary_sync(&schema, SECRET_COLLECTION_DEFAULT, "Binary fixture", value, NULL, &error, "test-id", "mime-roundtrip", NULL);
 secret_value_unref(value);
 if (!stored || error) goto fail;
 SecretValue *read = secret_password_lookup_binary_sync(&schema, NULL, &error, "test-id", "mime-roundtrip", NULL);
 if (!read || error) goto fail;
 gsize length = 0;
 const char *bytes = secret_value_get(read, &length);
 gboolean matches = length == sizeof binary && !memcmp(bytes, binary, length) && !strcmp(secret_value_get_content_type(read), mime);
 secret_value_unref(read);
 if (!matches) goto fail;
 if (!secret_password_store_sync(&schema, SECRET_COLLECTION_DEFAULT, "Text replacement", "", NULL, &error, "test-id", "mime-roundtrip", NULL)) goto fail;
 read = secret_password_lookup_binary_sync(&schema, NULL, &error, "test-id", "mime-roundtrip", NULL);
 if (!read || error) goto fail;
 bytes = secret_value_get(read, &length);
 matches = length == 0 && !strcmp(secret_value_get_content_type(read), "text/plain");
 secret_value_unref(read);
 if (!matches) goto fail;
 if (!secret_password_clear_sync(&schema, NULL, &error, "test-id", "mime-roundtrip", NULL)) goto fail;
 g_print("ROUNDTRIP PASS: encrypted create/read/replace/read/delete/absent\n");
 return 0;
fail:
 g_printerr("FAIL: %s\n", error ? error->message : "value mismatch or missing result");
 g_clear_error(&error);
 return 1;
}
