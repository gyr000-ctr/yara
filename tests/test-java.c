#include <string.h>
#include <yara.h>

#include "util.h"

// Minimal hand-crafted Java class file.
//
//   public class com.example.Hello extends java.lang.Object
//       implements java.io.Serializable
//
// Constant pool:
//   #1  Class               -> #2   (com/example/Hello)
//   #2  Utf8                "com/example/Hello"
//   #3  Class               -> #4   (java/lang/Object)
//   #4  Utf8                "java/lang/Object"
//   #5  Class               -> #6   (java/io/Serializable)
//   #6  Utf8                "java/io/Serializable"
//   #7  Fieldref            #1.#8
//   #8  NameAndType         #9:#10  (count:I)
//   #9  Utf8                "count"
//   #10 Utf8                "I"
//   #11 Methodref           #3.#12
//   #12 NameAndType         #13:#14 (<init>:()V)
//   #13 Utf8                "<init>"
//   #14 Utf8                "()V"
//   #15 InterfaceMethodref  #5.#16
//   #16 NameAndType         #17:#18 (run:()V)
//   #17 Utf8                "run"
//   #18 Utf8                "()V"
//   #19 Long                0x0102030405060708  (takes slots #19 and #20)
//
// After the constant pool: access_flags = 0x0021, this_class = #1,
// super_class = #3, one interface (#5).

static uint8_t CLASS_FILE[] = {
    0xCA, 0xFE, 0xBA, 0xBE,              // magic
    0x00, 0x00,                          // minor_version = 0
    0x00, 0x34,                          // major_version = 52
    0x00, 0x15,                          // constant_pool_count = 21
    0x07, 0x00, 0x02,                    // #1 Class -> #2
    0x01, 0x00, 0x11, 'c',  'o',  'm',   // #2 Utf8 "com/example/Hello"
    '/',  'e',  'x',  'a',  'm',  'p',
    'l',  'e',  '/',  'H',  'e',  'l',
    'l',  'o',
    0x07, 0x00, 0x04,                    // #3 Class -> #4
    0x01, 0x00, 0x10, 'j',  'a',  'v',   // #4 Utf8 "java/lang/Object"
    'a',  '/',  'l',  'a',  'n',  'g',
    '/',  'O',  'b',  'j',  'e',  'c',
    't',
    0x07, 0x00, 0x06,                    // #5 Class -> #6
    0x01, 0x00, 0x14, 'j',  'a',  'v',   // #6 Utf8 "java/io/Serializable"
    'a',  '/',  'i',  'o',  '/',  'S',
    'e',  'r',  'i',  'a',  'l',  'i',
    'z',  'a',  'b',  'l',  'e',
    0x09, 0x00, 0x01, 0x00, 0x08,        // #7 Fieldref #1.#8
    0x0C, 0x00, 0x09, 0x00, 0x0A,        // #8 NameAndType #9:#10
    0x01, 0x00, 0x05, 'c',  'o',  'u',   // #9 Utf8 "count"
    'n',  't',
    0x01, 0x00, 0x01, 'I',               // #10 Utf8 "I"
    0x0A, 0x00, 0x03, 0x00, 0x0C,        // #11 Methodref #3.#12
    0x0C, 0x00, 0x0D, 0x00, 0x0E,        // #12 NameAndType #13:#14
    0x01, 0x00, 0x06, '<',  'i',  'n',   // #13 Utf8 "<init>"
    'i',  't',  '>',
    0x01, 0x00, 0x03, '(',  ')',  'V',   // #14 Utf8 "()V"
    0x0B, 0x00, 0x05, 0x00, 0x10,        // #15 InterfaceMethodref #5.#16
    0x0C, 0x00, 0x11, 0x00, 0x12,        // #16 NameAndType #17:#18
    0x01, 0x00, 0x03, 'r',  'u',  'n',   // #17 Utf8 "run"
    0x01, 0x00, 0x03, '(',  ')',  'V',   // #18 Utf8 "()V"
    0x05, 0x01, 0x02, 0x03, 0x04,        // #19 Long (slots #19-#20)
    0x05, 0x06, 0x07, 0x08,
    0x00, 0x21,                          // access_flags
    0x00, 0x01,                          // this_class = #1
    0x00, 0x03,                          // super_class = #3
    0x00, 0x01,                          // interfaces_count = 1
    0x00, 0x05,                          // interfaces[0] = #5
};

// Offsets into CLASS_FILE used for patching malformed variants.
#define OFF_MAJOR_VERSION 6
#define OFF_CP_COUNT 8
#define OFF_COUNT_UTF8_TAG 91   // Tag byte of the Utf8 "count" entry (#9).
#define OFF_COUNT_UTF8_LEN 92   // Length byte pair of the same entry.
#define OFF_COUNT_UTF8_DATA 94  // First character of "count".
#define OFF_LONG_TAG 150        // Tag byte of the Long entry (#19).
#define OFF_THIS_CLASS 161

static int dummy_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
  return CALLBACK_CONTINUE;
}

// Asserts that scanning the blob with the given rule fails with the
// expected error (used for malformed class files, where the module load
// must fail instead of reading out of bounds).
static void assert_scan_error_blob(
    const char* rule,
    const uint8_t* blob,
    size_t blob_size,
    int expected_error)
{
  YR_RULES* rules;

  if (compile_rule((char*) rule, &rules) != ERROR_SUCCESS)
  {
    fprintf(stderr, "failed to compile rule << %s >>\n", rule);
    exit(EXIT_FAILURE);
  }

  int result = yr_rules_scan_mem(
      rules, (uint8_t*) blob, blob_size, 0, dummy_callback, NULL, 0);

  yr_rules_destroy(rules);

  if (result != expected_error)
  {
    fprintf(
        stderr,
        "expecting scan error %d but got %d for rule << %s >>\n",
        expected_error,
        result,
        rule);
    exit(EXIT_FAILURE);
  }
}

// Asserts that a malformed variant of CLASS_FILE (produced by patching one
// or two bytes, or by truncating) makes the java module fail to load with
// ERROR_INVALID_FILE.
static void assert_malformed(
    size_t patch_off,
    uint8_t patch_value,
    size_t truncate_to)
{
  uint8_t blob[sizeof(CLASS_FILE)];
  memcpy(blob, CLASS_FILE, sizeof(CLASS_FILE));

  if (patch_off != (size_t) -1)
    blob[patch_off] = patch_value;

  if (truncate_to == 0 || truncate_to > sizeof(CLASS_FILE))
    truncate_to = sizeof(CLASS_FILE);

  assert_scan_error_blob(
      "import \"java\" rule test { condition: java.major_version == 52 }",
      blob,
      truncate_to,
      ERROR_INVALID_FILE);
}

int main(int argc, char** argv)
{
  int result = 0;

  YR_DEBUG_INITIALIZE();
  YR_DEBUG_FPRINTF(1, stderr, "+ %s() { // in %s\n", __FUNCTION__, argv[0]);

  yr_initialize();

  // Sanity checks for the patch offsets into CLASS_FILE.
  assert_true_expr(CLASS_FILE[OFF_COUNT_UTF8_TAG] == 0x01);
  assert_true_expr(CLASS_FILE[OFF_COUNT_UTF8_LEN] == 0x00);
  assert_true_expr(CLASS_FILE[OFF_COUNT_UTF8_LEN + 1] == 0x05);
  assert_true_expr(CLASS_FILE[OFF_COUNT_UTF8_DATA] == 'c');
  assert_true_expr(CLASS_FILE[OFF_LONG_TAG] == 0x05);
  assert_true_expr(CLASS_FILE[OFF_THIS_CLASS] == 0x00);
  assert_true_expr(CLASS_FILE[OFF_THIS_CLASS + 1] == 0x01);

  // Header fields.
  assert_true_rule_blob(
      "import \"java\" rule test { condition: java.major_version == 52 }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: java.minor_version == 0 }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: java.constant_pool_count == 21 }",
      CLASS_FILE);

  // Constant pool entry counts.
  assert_true_rule_blob(
      "import \"java\" rule test { condition: java.number_of_classes == 3 }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: java.number_of_fields == 1 }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: java.number_of_methods == 2 }",
      CLASS_FILE);

  // Class names in fully qualified (dotted) form.
  assert_true_rule_blob(
      "import \"java\" rule test { condition: \
        java.this_class == \"com.example.Hello\" }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: \
        java.super_class == \"java.lang.Object\" }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: java.interfaces_count == 1 }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: \
        java.interfaces[0] == \"java.io.Serializable\" }",
      CLASS_FILE);

  // Field and method references, by index.
  assert_true_rule_blob(
      "import \"java\" rule test { condition: \
        java.field_refs[0].class_name == \"com.example.Hello\" and \
        java.field_refs[0].name == \"count\" and \
        java.field_refs[0].descriptor == \"I\" and \
        java.field_refs[0].signature == \"com.example.Hello#count:I\" }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: \
        java.method_refs[0].signature == \"java.lang.Object#<init>:()V\" }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: \
        java.method_refs[1].signature == \"java.io.Serializable#run:()V\" }",
      CLASS_FILE);

  // Iteration over references and interfaces.
  assert_true_rule_blob(
      "import \"java\" rule test { condition: \
        for any r in java.method_refs : ( r.name == \"run\" ) }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: \
        for any r in java.field_refs : ( \
          r.signature == \"com.example.Hello#count:I\" ) }",
      CLASS_FILE);

  assert_true_rule_blob(
      "import \"java\" rule test { condition: \
        for any i in java.interfaces : ( i == \"java.io.Serializable\" ) }",
      CLASS_FILE);

  // Constant pool tag constants.
  assert_true_rule_blob(
      "import \"java\" rule test { condition: java.CONSTANT_Class == 7 and \
        java.CONSTANT_Methodref == 10 and java.CONSTANT_Utf8 == 1 }",
      CLASS_FILE);

  // Files without the 0xCAFEBABE magic are not class files: the module
  // values are undefined but the scan succeeds.
  assert_false_rule(
      "import \"java\" rule test { condition: java.major_version == 52 }",
      "not a class file");

  // Unusual version numbers are exposed as-is, they are not an error.
  {
    uint8_t blob[sizeof(CLASS_FILE)];
    memcpy(blob, CLASS_FILE, sizeof(CLASS_FILE));
    blob[OFF_MAJOR_VERSION] = 0xFF;
    blob[OFF_MAJOR_VERSION + 1] = 0xFF;

    if (!matches_blob(
            "import \"java\" rule test { condition: \
              java.major_version == 65535 }",
            blob,
            sizeof(blob),
            NULL,
            0))
    {
      fprintf(stderr, "major_version 0xFFFF not exposed as 65535\n");
      exit(EXIT_FAILURE);
    }
  }

  // Malformed constant pool: illegal tag.
  assert_malformed(OFF_COUNT_UTF8_TAG, 0x63, 0);

  // Malformed constant pool: MUTF-8 length runs past the end of the file.
  assert_malformed(OFF_COUNT_UTF8_LEN, 0xFF, 0);
  assert_malformed(OFF_COUNT_UTF8_LEN + 1, 0xFF, 0);

  // Malformed constant pool: corrupted MUTF-8 (embedded zero byte).
  assert_malformed(OFF_COUNT_UTF8_DATA, 0x00, 0);

  // Malformed constant pool: corrupted MUTF-8 (lone continuation byte).
  assert_malformed(OFF_COUNT_UTF8_DATA, 0x80, 0);

  // Malformed class: this_class index out of range.
  assert_malformed(OFF_THIS_CLASS + 1, 0x64, 0);

  // Malformed class: constant_pool_count = 0.
  {
    uint8_t blob[sizeof(CLASS_FILE)];
    memcpy(blob, CLASS_FILE, sizeof(CLASS_FILE));
    blob[OFF_CP_COUNT] = 0x00;
    blob[OFF_CP_COUNT + 1] = 0x00;
    assert_scan_error_blob(
        "import \"java\" rule test { condition: true }",
        blob,
        sizeof(blob),
        ERROR_INVALID_FILE);
  }

  // Malformed constant pool: Long entry in the last slot has no second
  // slot (constant_pool_count = 20 makes #19 the last valid index).
  {
    uint8_t blob[sizeof(CLASS_FILE)];
    memcpy(blob, CLASS_FILE, sizeof(CLASS_FILE));
    blob[OFF_CP_COUNT + 1] = 0x14;
    assert_scan_error_blob(
        "import \"java\" rule test { condition: true }",
        blob,
        sizeof(blob),
        ERROR_INVALID_FILE);
  }

  // Malformed class: truncated file (header only, and mid constant pool).
  assert_malformed((size_t) -1, 0, 8);
  assert_malformed((size_t) -1, 0, 30);
  assert_malformed((size_t) -1, 0, sizeof(CLASS_FILE) - 3);

  yr_finalize();

  YR_DEBUG_FPRINTF(1, stderr, "} = %d // %s() in %s\n", result, __FUNCTION__, argv[0]);

  return result;
}
