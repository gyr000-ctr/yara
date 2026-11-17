/*
Copyright (c) 2026. The YARA Authors. All Rights Reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
this list of conditions and the following disclaimer in the documentation and/or
other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
may be used to endorse or promote products derived from this software without
specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

// YARA module for Java class files (0xCAFEBABE magic).
//
// The module parses the class file header and the constant pool only. Fields,
// methods, code and attributes are never touched, so parsing time is linear
// in the size of the constant pool (bounded by the file size) and the extra
// memory used is proportional to the number of constant pool entries, which
// is bounded by 65535 regardless of the file size. The file itself is never
// copied into memory; all reads are done in-place over the memory block with
// strict bounds checking.
//
// Any malformed structure (illegal constant pool tag, MUTF-8 string whose
// declared length runs past the end of the file, invalid MUTF-8 encoding,
// constant pool index out of range, truncated file) makes the module load
// fail with ERROR_INVALID_FILE instead of reading out of bounds. Scans of
// files that don't have the 0xCAFEBABE magic succeed with all module values
// undefined.

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <yara/endian.h>
#include <yara/mem.h>
#include <yara/modules.h>

#define MODULE_NAME java

// Constant pool tags (JVM spec, section 4.4).
#define JAVA_CONSTANT_Utf8 1
#define JAVA_CONSTANT_Integer 3
#define JAVA_CONSTANT_Float 4
#define JAVA_CONSTANT_Long 5
#define JAVA_CONSTANT_Double 6
#define JAVA_CONSTANT_Class 7
#define JAVA_CONSTANT_String 8
#define JAVA_CONSTANT_Fieldref 9
#define JAVA_CONSTANT_Methodref 10
#define JAVA_CONSTANT_InterfaceMethodref 11
#define JAVA_CONSTANT_NameAndType 12
#define JAVA_CONSTANT_MethodHandle 15
#define JAVA_CONSTANT_MethodType 16
#define JAVA_CONSTANT_Dynamic 17
#define JAVA_CONSTANT_InvokeDynamic 18
#define JAVA_CONSTANT_Module 19
#define JAVA_CONSTANT_Package 20

typedef struct
{
  uint8_t tag;
  uint32_t offset;  // Offset of the entry's content (byte after the tag).
} JAVA_CP_ENTRY;

typedef struct
{
  const uint8_t* data;
  size_t size;
  JAVA_CP_ENTRY* entries;  // Index 0 unused, valid indices are 1..cp_count-1.
  uint16_t cp_count;
} JAVA_CLASS;


static uint16_t read_u16(const uint8_t* p)
{
  return (uint16_t) ((p[0] << 8) | p[1]);
}


// Validates a Modified UTF-8 string as used in class files: no embedded zero
// bytes (NUL is encoded as 0xC0 0x80), only 1-, 2- and 3-byte sequences, no
// truncated or stray continuation bytes.
static bool java_valid_mutf8(const uint8_t* s, uint32_t length)
{
  uint32_t i = 0;

  while (i < length)
  {
    uint8_t b = s[i];

    if (b >= 0x01 && b <= 0x7F)
    {
      i++;
    }
    else if (b == 0xC0)  // Encoded NUL, only 0xC0 0x80 is valid.
    {
      if (i + 2 > length || s[i + 1] != 0x80)
        return false;
      i += 2;
    }
    else if (b >= 0xC2 && b <= 0xDF)
    {
      if (i + 2 > length || (s[i + 1] & 0xC0) != 0x80)
        return false;
      i += 2;
    }
    else if (b >= 0xE0 && b <= 0xEF)
    {
      if (i + 3 > length || (s[i + 1] & 0xC0) != 0x80 ||
          (s[i + 2] & 0xC0) != 0x80)
        return false;
      i += 3;
    }
    else
    {
      // 0x00, 0xC1, 4-byte lead bytes and stray continuation bytes.
      return false;
    }
  }

  return true;
}


// Returns true if idx is a valid constant pool index for an entry of the
// expected tag.
static bool java_valid_index(
    JAVA_CLASS* clazz,
    uint16_t idx,
    uint8_t expected_tag)
{
  return idx >= 1 && idx < clazz->cp_count &&
         clazz->entries[idx].tag == expected_tag;
}


// Returns a pointer to the bytes of a CONSTANT_Utf8 entry and its length.
// The index must have been validated with java_valid_index beforehand; the
// entry's bounds were checked while walking the constant pool.
static const uint8_t* java_utf8(JAVA_CLASS* clazz, uint16_t idx, uint16_t* len)
{
  uint32_t offset = clazz->entries[idx].offset;
  *len = read_u16(clazz->data + offset);
  return clazz->data + offset + 2;
}


// Sets a string field of the module to the name of a CONSTANT_Class entry,
// converting the internal "com/example/Foo" form to the fully qualified
// "com.example.Foo" form. The class index must have been validated
// beforehand, but the class' name_index is validated here.
static int java_set_class_name(
    JAVA_CLASS* clazz,
    YR_OBJECT* module_object,
    uint16_t class_idx,
    const char* field,
    ...)
{
  va_list args;
  char field_fmt[64];

  uint32_t offset = clazz->entries[class_idx].offset;
  uint16_t name_idx = read_u16(clazz->data + offset);

  if (!java_valid_index(clazz, name_idx, JAVA_CONSTANT_Utf8))
    return ERROR_INVALID_FILE;

  uint16_t len;
  const uint8_t* bytes = java_utf8(clazz, name_idx, &len);

  char* name = (char*) yr_malloc(len + 1);

  if (name == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  for (uint16_t i = 0; i < len; i++)
    name[i] = (bytes[i] == '/') ? '.' : (char) bytes[i];
  name[len] = '\0';

  va_start(args, field);
  vsnprintf(field_fmt, sizeof(field_fmt), field, args);
  va_end(args);

  int result = yr_set_string(name, module_object, field_fmt);

  yr_free(name);

  return result;
}


// Resolves a CONSTANT_Fieldref/Methodref/InterfaceMethodref entry and sets
// the corresponding fields in field_refs[i] or method_refs[i]. Returns an
// error if any constant pool index is out of range or has the wrong tag.
static int java_set_reference(
    JAVA_CLASS* clazz,
    YR_OBJECT* module_object,
    uint32_t entry_idx,
    const char* array_name,
    uint32_t array_idx)
{
  uint32_t offset = clazz->entries[entry_idx].offset;
  uint16_t class_idx = read_u16(clazz->data + offset);
  uint16_t nt_idx = read_u16(clazz->data + offset + 2);

  if (!java_valid_index(clazz, class_idx, JAVA_CONSTANT_Class) ||
      !java_valid_index(clazz, nt_idx, JAVA_CONSTANT_NameAndType))
    return ERROR_INVALID_FILE;

  uint32_t nt_offset = clazz->entries[nt_idx].offset;
  uint16_t name_idx = read_u16(clazz->data + nt_offset);
  uint16_t desc_idx = read_u16(clazz->data + nt_offset + 2);

  if (!java_valid_index(clazz, name_idx, JAVA_CONSTANT_Utf8) ||
      !java_valid_index(clazz, desc_idx, JAVA_CONSTANT_Utf8))
    return ERROR_INVALID_FILE;

  uint16_t class_len, name_len, desc_len;

  uint16_t class_name_idx =
      read_u16(clazz->data + clazz->entries[class_idx].offset);

  if (!java_valid_index(clazz, class_name_idx, JAVA_CONSTANT_Utf8))
    return ERROR_INVALID_FILE;

  const uint8_t* class_bytes = java_utf8(clazz, class_name_idx, &class_len);

  const uint8_t* name_bytes = java_utf8(clazz, name_idx, &name_len);
  const uint8_t* desc_bytes = java_utf8(clazz, desc_idx, &desc_len);

  // Build "class#name:descriptor" with the class name in fully qualified
  // (dotted) form.
  size_t sig_len = (size_t) class_len + 1 + name_len + 1 + desc_len;
  char* sig = (char*) yr_malloc(sig_len + 1);
  char* class_name = (char*) yr_malloc(class_len + 1);

  if (sig == NULL || class_name == NULL)
  {
    yr_free(sig);
    yr_free(class_name);
    return ERROR_INSUFFICIENT_MEMORY;
  }

  for (uint16_t i = 0; i < class_len; i++)
    class_name[i] = (class_bytes[i] == '/') ? '.' : (char) class_bytes[i];
  class_name[class_len] = '\0';

  char* p = sig;
  memcpy(p, class_name, class_len);
  p += class_len;
  *p++ = '#';
  memcpy(p, name_bytes, name_len);
  p += name_len;
  *p++ = ':';
  memcpy(p, desc_bytes, desc_len);
  p += desc_len;
  *p = '\0';

  char field[64];

  snprintf(field, sizeof(field), "%s[%u].class_name", array_name, array_idx);
  int result = yr_set_string(class_name, module_object, field);

  if (result == ERROR_SUCCESS)
  {
    snprintf(field, sizeof(field), "%s[%u].name", array_name, array_idx);
    result = yr_set_sized_string(
        (const char*) name_bytes, name_len, module_object, field);
  }

  if (result == ERROR_SUCCESS)
  {
    snprintf(field, sizeof(field), "%s[%u].descriptor", array_name, array_idx);
    result = yr_set_sized_string(
        (const char*) desc_bytes, desc_len, module_object, field);
  }

  if (result == ERROR_SUCCESS)
  {
    snprintf(field, sizeof(field), "%s[%u].signature", array_name, array_idx);
    result = yr_set_sized_string(sig, sig_len, module_object, field);
  }

  yr_free(sig);
  yr_free(class_name);

  return result;
}


// Parses the class file in data and populates the module object. Returns
// ERROR_INVALID_FILE if the file is malformed.
static int java_parse(
    YR_OBJECT* module_object,
    const uint8_t* data,
    size_t size)
{
  // Header is magic(4) + minor_version(2) + major_version(2) +
  // constant_pool_count(2).
  if (size < 10)
    return ERROR_INVALID_FILE;

  uint16_t minor = read_u16(data + 4);
  uint16_t major = read_u16(data + 6);
  uint16_t cp_count = read_u16(data + 8);

  // constant_pool_count is the number of entries plus one, so it can't be 0.
  if (cp_count == 0)
    return ERROR_INVALID_FILE;

  JAVA_CLASS clazz;
  clazz.data = data;
  clazz.size = size;
  clazz.cp_count = cp_count;
  clazz.entries = (JAVA_CP_ENTRY*) yr_calloc(cp_count, sizeof(JAVA_CP_ENTRY));

  if (clazz.entries == NULL)
    return ERROR_INSUFFICIENT_MEMORY;

  int result = ERROR_SUCCESS;
  int64_t num_classes = 0;
  int64_t num_methods = 0;
  int64_t num_fields = 0;

  // Walk the constant pool. "off" never exceeds "size" when entering each
  // iteration, so "size - off" can't underflow.
  size_t off = 10;

  for (uint32_t i = 1; i < cp_count; i++)
  {
    if (off >= size)
    {
      result = ERROR_INVALID_FILE;  // Truncated constant pool.
      goto cleanup;
    }

    uint8_t tag = data[off];
    clazz.entries[i].tag = tag;
    clazz.entries[i].offset = (uint32_t) (off + 1);

    size_t need;  // Size of the entry including the tag byte.

    switch (tag)
    {
    case JAVA_CONSTANT_Utf8:
    {
      if (size - off < 3)
      {
        result = ERROR_INVALID_FILE;
        goto cleanup;
      }

      uint16_t len = read_u16(data + off + 1);

      if (size - off - 3 < len ||
          !java_valid_mutf8(data + off + 3, len))
      {
        result = ERROR_INVALID_FILE;
        goto cleanup;
      }

      off += 3 + len;
      continue;
    }
    case JAVA_CONSTANT_Integer:
    case JAVA_CONSTANT_Float:
      need = 5;
      break;
    case JAVA_CONSTANT_Long:
    case JAVA_CONSTANT_Double:
      // These entries take up two constant pool slots.
      if (size - off < 9)
      {
        result = ERROR_INVALID_FILE;
        goto cleanup;
      }
      i++;
      if (i >= cp_count)
      {
        // A Long/Double in the last slot has no valid second slot.
        result = ERROR_INVALID_FILE;
        goto cleanup;
      }
      off += 9;
      continue;
    case JAVA_CONSTANT_Class:
      num_classes++;
      need = 3;
      break;
    case JAVA_CONSTANT_String:
    case JAVA_CONSTANT_MethodType:
    case JAVA_CONSTANT_Module:
    case JAVA_CONSTANT_Package:
      need = 3;
      break;
    case JAVA_CONSTANT_Fieldref:
      num_fields++;
      need = 5;
      break;
    case JAVA_CONSTANT_Methodref:
    case JAVA_CONSTANT_InterfaceMethodref:
      num_methods++;
      need = 5;
      break;
    case JAVA_CONSTANT_NameAndType:
    case JAVA_CONSTANT_Dynamic:
    case JAVA_CONSTANT_InvokeDynamic:
      need = 5;
      break;
    case JAVA_CONSTANT_MethodHandle:
      need = 4;
      break;
    default:
      // Illegal constant pool tag.
      result = ERROR_INVALID_FILE;
      goto cleanup;
    }

    if (size - off < need)
    {
      result = ERROR_INVALID_FILE;  // Truncated entry.
      goto cleanup;
    }

    off += need;
  }

  // access_flags(2) + this_class(2) + super_class(2) + interfaces_count(2).
  if (size - off < 8)
  {
    result = ERROR_INVALID_FILE;
    goto cleanup;
  }

  uint16_t this_class = read_u16(data + off + 2);
  uint16_t super_class = read_u16(data + off + 4);
  uint16_t interfaces_count = read_u16(data + off + 6);

  off += 8;

  if (size - off < (size_t) interfaces_count * 2)
  {
    result = ERROR_INVALID_FILE;  // Truncated interfaces table.
    goto cleanup;
  }

  if (!java_valid_index(&clazz, this_class, JAVA_CONSTANT_Class))
  {
    result = ERROR_INVALID_FILE;
    goto cleanup;
  }

  // super_class may be 0 only for java.lang.Object.
  if (super_class != 0 &&
      !java_valid_index(&clazz, super_class, JAVA_CONSTANT_Class))
  {
    result = ERROR_INVALID_FILE;
    goto cleanup;
  }

  for (uint16_t i = 0; i < interfaces_count; i++)
  {
    if (!java_valid_index(
            &clazz, read_u16(data + off + 2 * i), JAVA_CONSTANT_Class))
    {
      result = ERROR_INVALID_FILE;
      goto cleanup;
    }
  }

  yr_set_integer(major, module_object, "major_version");
  yr_set_integer(minor, module_object, "minor_version");
  yr_set_integer(cp_count, module_object, "constant_pool_count");
  yr_set_integer(num_classes, module_object, "number_of_classes");
  yr_set_integer(num_methods, module_object, "number_of_methods");
  yr_set_integer(num_fields, module_object, "number_of_fields");
  yr_set_integer(interfaces_count, module_object, "interfaces_count");

  result = java_set_class_name(&clazz, module_object, this_class, "this_class");

  if (result != ERROR_SUCCESS)
    goto cleanup;

  if (super_class != 0)
  {
    result =
        java_set_class_name(&clazz, module_object, super_class, "super_class");

    if (result != ERROR_SUCCESS)
      goto cleanup;
  }

  for (uint16_t i = 0; i < interfaces_count; i++)
  {
    result = java_set_class_name(
        &clazz,
        module_object,
        read_u16(data + off + 2 * i),
        "interfaces[%u]",
        (unsigned int) i);

    if (result != ERROR_SUCCESS)
      goto cleanup;
  }

  // Resolve field and method references.
  uint32_t field_idx = 0;
  uint32_t method_idx = 0;

  for (uint32_t i = 1; i < cp_count; i++)
  {
    uint8_t tag = clazz.entries[i].tag;

    if (tag == JAVA_CONSTANT_Fieldref)
    {
      result = java_set_reference(
          &clazz, module_object, i, "field_refs", field_idx++);
    }
    else if (
        tag == JAVA_CONSTANT_Methodref ||
        tag == JAVA_CONSTANT_InterfaceMethodref)
    {
      result = java_set_reference(
          &clazz, module_object, i, "method_refs", method_idx++);
    }

    if (result != ERROR_SUCCESS)
      goto cleanup;
  }

  result = ERROR_SUCCESS;

cleanup:
  yr_free(clazz.entries);
  return result;
}


begin_declarations
  declare_integer("major_version");
  declare_integer("minor_version");
  declare_integer("constant_pool_count");
  declare_integer("number_of_classes");
  declare_integer("number_of_methods");
  declare_integer("number_of_fields");

  declare_string("this_class");
  declare_string("super_class");
  declare_integer("interfaces_count");
  declare_string_array("interfaces");

  begin_struct_array("field_refs")
    declare_string("class_name");
    declare_string("name");
    declare_string("descriptor");
    declare_string("signature");
  end_struct_array("field_refs")

  begin_struct_array("method_refs")
    declare_string("class_name");
    declare_string("name");
    declare_string("descriptor");
    declare_string("signature");
  end_struct_array("method_refs")

  declare_integer("CONSTANT_Utf8");
  declare_integer("CONSTANT_Integer");
  declare_integer("CONSTANT_Float");
  declare_integer("CONSTANT_Long");
  declare_integer("CONSTANT_Double");
  declare_integer("CONSTANT_Class");
  declare_integer("CONSTANT_String");
  declare_integer("CONSTANT_Fieldref");
  declare_integer("CONSTANT_Methodref");
  declare_integer("CONSTANT_InterfaceMethodref");
  declare_integer("CONSTANT_NameAndType");
  declare_integer("CONSTANT_MethodHandle");
  declare_integer("CONSTANT_MethodType");
  declare_integer("CONSTANT_Dynamic");
  declare_integer("CONSTANT_InvokeDynamic");
  declare_integer("CONSTANT_Module");
  declare_integer("CONSTANT_Package");
end_declarations


int module_load(
    YR_SCAN_CONTEXT* context,
    YR_OBJECT* module_object,
    void* module_data,
    size_t module_data_size)
{
  YR_MEMORY_BLOCK* block;
  YR_MEMORY_BLOCK_ITERATOR* iterator = context->iterator;

  yr_set_integer(JAVA_CONSTANT_Utf8, module_object, "CONSTANT_Utf8");
  yr_set_integer(JAVA_CONSTANT_Integer, module_object, "CONSTANT_Integer");
  yr_set_integer(JAVA_CONSTANT_Float, module_object, "CONSTANT_Float");
  yr_set_integer(JAVA_CONSTANT_Long, module_object, "CONSTANT_Long");
  yr_set_integer(JAVA_CONSTANT_Double, module_object, "CONSTANT_Double");
  yr_set_integer(JAVA_CONSTANT_Class, module_object, "CONSTANT_Class");
  yr_set_integer(JAVA_CONSTANT_String, module_object, "CONSTANT_String");
  yr_set_integer(JAVA_CONSTANT_Fieldref, module_object, "CONSTANT_Fieldref");
  yr_set_integer(JAVA_CONSTANT_Methodref, module_object, "CONSTANT_Methodref");
  yr_set_integer(
      JAVA_CONSTANT_InterfaceMethodref,
      module_object,
      "CONSTANT_InterfaceMethodref");
  yr_set_integer(
      JAVA_CONSTANT_NameAndType, module_object, "CONSTANT_NameAndType");
  yr_set_integer(
      JAVA_CONSTANT_MethodHandle, module_object, "CONSTANT_MethodHandle");
  yr_set_integer(JAVA_CONSTANT_MethodType, module_object, "CONSTANT_MethodType");
  yr_set_integer(JAVA_CONSTANT_Dynamic, module_object, "CONSTANT_Dynamic");
  yr_set_integer(
      JAVA_CONSTANT_InvokeDynamic, module_object, "CONSTANT_InvokeDynamic");
  yr_set_integer(JAVA_CONSTANT_Module, module_object, "CONSTANT_Module");
  yr_set_integer(JAVA_CONSTANT_Package, module_object, "CONSTANT_Package");

  foreach_memory_block(iterator, block)
  {
    const uint8_t* block_data = yr_fetch_block_data(block);

    if (block_data == NULL || block->size < 4)
      continue;

    if (block_data[0] == 0xCA && block_data[1] == 0xFE &&
        block_data[2] == 0xBA && block_data[3] == 0xBE)
    {
      return java_parse(module_object, block_data, block->size);
    }
  }

  // Not a class file, the scan succeeds with all module values undefined.
  return ERROR_SUCCESS;
}


int module_unload(YR_OBJECT* module_object)
{
  return ERROR_SUCCESS;
}


int module_initialize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}


int module_finalize(YR_MODULE* module)
{
  return ERROR_SUCCESS;
}

#undef MODULE_NAME
