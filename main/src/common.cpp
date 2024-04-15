#include "dr_api.h"
#include "dr_tools.h"
#include "drx.h"

#include "common.h"

namespace app {

/*
#include <array>
#include <bit>
#include <concepts>
#include <cstdint>
#include <fstream>
#include <memory>
#include <vector>

template <typename T>
constexpr size_t tls_extra_alloc_size = sizeof(void*) + ((alignof(T) <= sizeof(void*)) ? 0 : (alignof(T) - 1));

template <typename T>
T* TlsConstruct(void* drcontext, auto&&... ctor_args) {
  constexpr size_t size = sizeof(T) + tls_extra_alloc_size<T>;
  void* allocation_base = dr_thread_alloc(drcontext, size);
  if (!allocation_base) return nullptr;

  void* object_base = reinterpret_cast<void*>(reinterpret_cast<char*>(allocation_base) + sizeof(void*));
  size_t space = size;
  void* ret = std::align(alignof(T), sizeof(T), object_base, space);
  DR_ASSERT(ret != nullptr);

  void** base_ptr = reinterpret_cast<void**>(reinterpret_cast<char*>(object_base) - sizeof(void*));
  *base_ptr = allocation_base;

  return new (reinterpret_cast<T*>(object_base)) T(std::forward<decltype(ctor_args)>(ctor_args)...);
}

template <typename T>
void TlsDestruct(void* drcontext, T* ptr) {
  ptr->~T();
  void** base_ptr = reinterpret_cast<void**>(reinterpret_cast<char*>(ptr) - sizeof(void*));
  dr_thread_free(drcontext, *base_ptr, sizeof(T) + tls_extra_alloc_size<T>);
}

struct MemoryAccessInfo {
  uintptr_t instruction_address;
  uintptr_t memory_address;
  uint16_t access_size;
};

template <std::integral T>
static void WriteLE(std::ofstream& file, T const& x) {
  if constexpr (std::endian::native == std::endian::little) {
    auto memory = reinterpret_cast<char const*>(&x);
    file.write(memory, sizeof(T));
  } else {
    static_assert(std::endian::native == std::endian::big);
    auto memory_be = reinterpret_cast<char const*>(&x);
    std::array<char, sizeof(T)> memory_le;
    for (size_t i = 0; i < sizeof(T); i++) {
      memory_le[sizeof(T) - i - 1] = memory_be[i];
    }
    file.write(memory_le.begin(), memory_le.size());
  }
}

template <std::integral T>
static bool ReadLE(std::ifstream& file, T* out) {
  char* base = reinterpret_cast<char*>(out);
  if constexpr (std::endian::native == std::endian::little) {
    file.read(base, sizeof(T));
    if (file.gcount() < sizeof(T)) return false;
  } else {
    static_assert(std::endian::native == std::endian::big);
    std::array<char, sizeof(T)> memory_le;
    file.read(memory_le.begin(), sizeof(T));
    if (file.gcount() < sizeof(T)) return false;
    for (size_t i = 0; i < sizeof(T); i++) {
      base[sizeof(T) - i - 1] = memory_le[i];
    }
  }
  return true;
}

class ThreadData {
 public:
  inline ThreadData(std::string const& filename) : LogFile(filename, std::ios::binary) {
    Buffer.reserve(buffer_capacity);
  }

  inline void Write(MemoryAccessInfo const& info) {
    Buffer.push_back(info);
    if (Buffer.size() >= buffer_capacity) {
      for (auto const& info : Buffer) {
        WriteLE(LogFile, info.instruction_address);
        WriteLE(LogFile, info.memory_address);
        WriteLE(LogFile, info.access_size);
      }
      Buffer.clear();
    }
  }

 private:
  static constexpr size_t buffer_capacity = 8192;

  std::ofstream LogFile;
  std::vector<MemoryAccessInfo> Buffer;
};
*/

///////////////////////////////////////////////////////////////////////////////
// String
///////////////////////////////////////////////////////////////////////////////

bool IsWhitespace(uint8_t character) {
  if (character == ' ') return true;
  if (character == '\t') return true;
  if (character == '\n') return true;
  if (character == '\r') return true;
  return false;
}

static String Allocate(void* drcontext, const char* cStr) {
  size_t len = strlen(cStr);
  String result = DrThreadAllocArray<uint8_t>(drcontext, len + 1);
  memcpy(result.address, cStr, len);
  result.address[result.count] = '\0';
  return result;
}

static String Allocate(void* drcontext, String string) {
  String result = DrThreadAllocArray<uint8_t>(drcontext, string.count + 1);
  memcpy(result.address, string.address, string.count);
  result.address[result.count] = '\0';
  return result;
}

static Array<char> AllocateCStr(void* drcontext, String string) {
  Array<char> cstr = DrThreadAllocArray<char>(drcontext, string.count + 1);
  memcpy(cstr.address, string.address, string.count);
  cstr[cstr.count - 1] = '\0';
  return cstr;
}

static String kLineEndingChars = Wrap("\n\r");
static String kWhitespaceChars = Wrap(" \t\n\r");
static String kSlashChars = Wrap("/\\");

String Substring(String string, size_t startIndex, size_t length) {
  DR_ASSERT(startIndex <= string.count);
  DR_ASSERT((startIndex + length) <= string.count);

  String result;
  result.count = length;
  result.address = string.address + startIndex;
  return result;
}

bool operator==(String lhs, String rhs) {
  if (lhs.count != rhs.count) return false;
  return memcmp(lhs.address, rhs.address, lhs.count) == 0;
}

bool operator==(String lhs, const char* rhs) {
  size_t rhsLength = strlen(rhs);
  if (lhs.count != rhsLength) return false;
  return memcmp(lhs.address, rhs, lhs.count) == 0;
}

bool operator==(const char* lhs, String rhs) {
  size_t lhsLength = strlen(lhs);
  if (lhsLength != rhs.count) return false;
  return memcmp(lhs, rhs.address, lhsLength) == 0;
}

bool PrefixEquals(String string, String prefix) {
  if (string.count < prefix.count) return false;
  return memcmp(string.address, prefix.address, prefix.count) == 0;
}

bool SuffixEquals(String string, String suffix) {
  if (string.count < suffix.count) return false;
  uint8_t* Substring = string.address + string.count - suffix.count;
  return memcmp(Substring, suffix.address, suffix.count) == 0;
}

bool CompareCaseInsensitive(const void* m1, const void* m2, size_t length) {
  uint8_t* bytes1 = (uint8_t*)m1;
  uint8_t* bytes2 = (uint8_t*)m2;
  for (size_t i = 0; i < length; i++) {
    uint8_t a = bytes1[i];
    uint8_t b = bytes2[i];
    if (a == b) continue;

    if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
    if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
    if (a == b) continue;

    return false;
  }

  return true;
}

bool CompareCaseInsensitive(String lhs, String rhs) {
  if (lhs.count != rhs.count) return false;
  return CompareCaseInsensitive(lhs.address, rhs.address, lhs.count);
}

bool PrefixEqualsCaseInsensitive(String string, String prefix) {
  if (string.count < prefix.count) return false;
  return CompareCaseInsensitive(string.address, prefix.address, prefix.count);
}

bool SuffixEqualsCaseInsensitive(String string, String suffix) {
  if (string.count < suffix.count) return false;
  uint8_t* Substring = string.address + string.count - suffix.count;
  return CompareCaseInsensitive(Substring, suffix.address, suffix.count);
}

size_t FindFirstOccurance(String string, uint8_t of) {
  for (ssize_t i = 0; i < (ssize_t)string.count; i++)
    if (string[i] == of) return i;

  return kNotFound;
}

size_t FindFirstOccurance(String string, String of) {
  if (string.count < of.count) return kNotFound;

  for (ssize_t i = 0; i <= (ssize_t)(string.count - of.count); i++)
    if (memcmp(string.address + i, of.address, of.count) == 0) return i;

  return kNotFound;
}

size_t FindFirstOccuranceOfAny(String string, String anyOf) {
  for (ssize_t i = 0; i < (ssize_t)string.count; i++) {
    uint8_t c = string[i];

    for (size_t j = 0; j < anyOf.count; j++) {
      uint8_t c2 = anyOf[j];
      if (c == c2) return i;
    }
  }

  return kNotFound;
}

size_t FindLastOccurance(String string, uint8_t of) {
  for (ssize_t i = (ssize_t)string.count - 1; i >= 0; i--)
    if (string[i] == of) return i;

  return kNotFound;
}

size_t FindLastOccurance(String string, String of) {
  if (string.count < of.count) return kNotFound;

  for (ssize_t i = (ssize_t)(string.count - of.count); i >= 0; i--)
    if (memcmp(string.address + i, of.address, of.count) == 0) return i;

  return kNotFound;
}

size_t FindLastOccuranceOfAny(String string, String anyOf) {
  for (ssize_t i = (ssize_t)string.count - 1; i >= 0; i--) {
    uint8_t c = string[i];

    for (size_t j = 0; j < anyOf.count; j++) {
      uint8_t c2 = anyOf[j];
      if (c == c2) return i;
    }
  }

  return kNotFound;
}

String Consume(String string, size_t amount) {
  DR_ASSERT(amount <= string.count);
  string.address += amount;
  string.count -= amount;
  return string;
}

void Consume(String* string, size_t amount) {
  DR_ASSERT(amount <= string->count);
  string->address += amount;
  string->count -= amount;
}

String Take(String* string, size_t amount) {
  DR_ASSERT(amount <= string->count);
  String result = {amount, string->address};
  string->address += amount;
  string->count -= amount;
  return result;
}

void ConsumeWhitespace(String* string) {
  while (string->count && IsWhitespace(string->address[0])) Consume(string, 1);
}

String ConsumeLine(String* string) {
  ConsumeWhitespace(string);

  size_t lineLength = FindFirstOccuranceOfAny(*string, kLineEndingChars);
  if (lineLength == kNotFound) lineLength = string->count;

  String line = Substring(*string, 0, lineLength);
  Consume(string, lineLength);

  return line;
}

String ConsumeLinePreserveWhitespace(String* string) {
  size_t lineLength = FindFirstOccuranceOfAny(*string, Wrap("\n\r"));
  if (lineLength == kNotFound) lineLength = string->count;

  String line = Substring(*string, 0, lineLength);
  Consume(string, lineLength);

  // If we've found the line ending, Consume it.
  if (string->count) {
    size_t endingLength = 1;
    if (string->count > 1) {
      // Handle two-uint8_t line endings.
      uint8_t c1 = string->address[0];
      uint8_t c2 = string->address[1];
      if ((c1 == '\n' && c2 == '\r') || (c1 == '\r' && c2 == '\n')) endingLength++;
    }
    Consume(string, endingLength);
  }

  return line;
}

String ConsumeUntil(String* string, uint8_t untilWhat) {
  ConsumeWhitespace(string);

  size_t leftLength = FindFirstOccurance(*string, untilWhat);
  if (leftLength == kNotFound) leftLength = string->count;

  String left = Substring(*string, 0, leftLength);
  Consume(string, leftLength);

  // If we've found the delimiter, Consume it.
  if (string->count) Consume(string, 1);

  return left;
}

String ConsumeUntilPreserveWhitespace(String* string, String untilWhat) {
  size_t leftLength = FindFirstOccurance(*string, untilWhat);
  if (leftLength == kNotFound) leftLength = string->count;

  String left = Substring(*string, 0, leftLength);
  Consume(string, leftLength);

  // If we've found the delimiter, Consume it.
  if (string->count) Consume(string, untilWhat.count);

  return left;
}

String ConsumeUntil(String* string, String untilWhat) {
  ConsumeWhitespace(string);
  return ConsumeUntilPreserveWhitespace(string, untilWhat);
}

String ConsumeUntilAny(String* string, String untilWhat) {
  ConsumeWhitespace(string);

  size_t leftLength = FindFirstOccuranceOfAny(*string, untilWhat);
  if (leftLength == kNotFound) leftLength = string->count;

  String left = Substring(*string, 0, leftLength);
  Consume(string, leftLength);

  // If we've found the delimiter, Consume it.
  if (string->count) Consume(string, 1);

  return left;
}

String ConsumeUntilWhitespace(String* string) { return ConsumeUntilAny(string, kWhitespaceChars); }

String ConsumeUntilLast(String* string, uint8_t untilWhat) {
  size_t leftLength = FindLastOccurance(*string, untilWhat);
  if (leftLength == kNotFound) leftLength = string->count;

  String left = Substring(*string, 0, leftLength);
  Consume(string, leftLength);

  // If we've found the delimiter, Consume it.
  if (string->count) Consume(string, 1);

  return left;
}

String ConsumeUntilLast(String* string, String untilWhat) {
  size_t leftLength = FindLastOccurance(*string, untilWhat);
  if (leftLength == kNotFound) leftLength = string->count;

  String left = Substring(*string, 0, leftLength);
  Consume(string, leftLength);

  // If we've found the delimiter, Consume it.
  if (string->count) Consume(string, untilWhat.count);

  return left;
}

String trim(String string) {
  while (string.count && IsWhitespace(string[0])) Consume(&string, 1);
  while (string.count && IsWhitespace(string[string.count - 1])) string.count--;
  return string;
}

String trim_front(String string) {
  while (string.count && IsWhitespace(string[0])) Consume(&string, 1);
  return string;
}

String trim_back(String string) {
  while (string.count && IsWhitespace(string[string.count - 1])) string.count--;
  return string;
}

String Take(String* string, size_t amount);
void ConsumeWhitespace(String* string);

///////////////////////////////////////////////////////////////////////////////
// Filesystem
///////////////////////////////////////////////////////////////////////////////

file_t OpenUniqueFile(void* drcontext, client_id_t id, String nameBase, String extension, bool read, bool write) {
  String clientPath = Wrap(dr_get_client_path(id));
  String clientDir = ConsumeUntilLast(&clientPath, '/');
  String dir = Allocate(drcontext, clientDir);
  Defer(DrThreadFreeArray(drcontext, &dir));

  uint64_t flags = DR_FILE_ALLOW_LARGE;
  if (read) flags |= DR_FILE_READ;
  if (write) flags |= DR_FILE_WRITE_OVERWRITE;

  file_t file = drx_open_unique_appid_file(reinterpret_cast<char*>(dir.address), dr_get_process_id(),
                                           reinterpret_cast<char*>(nameBase.address),
                                           reinterpret_cast<char*>(extension.address), flags, NULL, 0);
  DR_ASSERT(file != INVALID_FILE);
  return file;
}

void BufferedFileWriter::Make(BufferedFileWriter* writer, void* drcontext, file_t file, size_t bufferSize) {
  *writer = {};
  writer->drcontext = drcontext;
  writer->file = file;
  writer->buffer = DrThreadAllocArray<uint8_t>(drcontext, bufferSize);
}

void BufferedFileWriter::FlushAndDestroy() {
  // Flushes our buffer.
  EnsureBufferSize(buffer.count);
  dr_flush_file(file);
  dr_close_file(file);
  DrThreadFreeArray(drcontext, &buffer);
  (*this) = {};
}

void BufferedFileWriter::EnsureBufferSize(size_t size) {
  DR_ASSERT(size <= buffer.count);
  if (cursor + size <= buffer.count) return;

  uint64_t attempts = 0;
  for (ssize_t remaining = cursor; remaining > 0;) {
    ssize_t written = dr_write_file(file, buffer.address, remaining);
    DR_ASSERT(written >= 0 && remaining >= written);
    remaining -= written;

    if (++attempts >= 1000) {
      DR_ASSERT_MSG(false, "Failed to write to file");
    }
  }

  cursor = 0;
}

void BufferedFileWriter::WriteString(String string) {
  WriteUint64LE(string.count);
  for (auto it : string) {
    WriteUint8LE(it);
  }
}

void BufferedFileReader::Make(BufferedFileReader* reader, void* drcontext, file_t file, size_t bufferSize) {
  *reader = {};
  reader->drcontext = drcontext;
  reader->file = file;
  bool ok = dr_file_size(file, &reader->fileSize);
  DR_ASSERT(ok);
  reader->buffer = DrThreadAllocArray<uint8_t>(drcontext, bufferSize);
}

void BufferedFileReader::Destroy() {
  dr_close_file(file);
  DrThreadFreeArray(drcontext, &buffer);
  (*this) = {};
}

bool BufferedFileReader::Read(Array<uint8_t> const& data) {
  for (size_t writeCursor = 0; writeCursor < data.count;) {
    // Refill the buffer if it's empty.
    if (bufferCursor >= bufferFilledTo) {
      // EOF
      if (fileCursor >= fileSize) return false;

      bufferCursor = 0;
      bufferFilledTo = 0;

      uint64_t attempts = 0;
      uint64_t remaining = min(fileSize - fileCursor, buffer.count);
      while (remaining) {
        ssize_t readed = dr_read_file(file, buffer.address + bufferFilledTo, remaining);
        DR_ASSERT(0 <= readed && readed <= remaining);
        remaining -= readed;
        fileCursor += readed;
        bufferFilledTo += readed;

        if (++attempts >= 1000) {
          DR_ASSERT_MSG(false, "Failed to read from file");
          return false;
        }
      }
    }

    size_t read = min(data.count - writeCursor, bufferFilledTo - bufferCursor);
    memcpy(data.address + writeCursor, buffer.address + bufferCursor, read);
    bufferCursor += read;
    writeCursor += read;
    DR_ASSERT(bufferCursor <= bufferFilledTo);
    DR_ASSERT(writeCursor <= data.count);
  }

  return true;
}

}  // namespace app
