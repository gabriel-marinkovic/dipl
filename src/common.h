#pragma once

#include "dr_api.h"

namespace app {

#if defined(__amd64__) || defined(__amd64) || defined(__x86_64__) || defined(__x86_64) || defined(_M_X64) || \
    defined(_M_AMD64)
  #define ARCHITECTURE_X64
#elif defined(i386) || defined(__i386) || defined(__i386__) || defined(_X86_) || defined(_M_IX86)
  #define ARCHITECTURE_X86
#else
  #error "Unrecognized CPU architecture."
#endif

#if defined(_WIN32)
  #define OS_WINDOWS
#elif defined(__linux__)
  #define OS_LINUX
#elif defined(__APPLE__) && defined(__MACH__)
  #define OS_MACOS
#else
  #error "Unrecognized operating system."
#endif

#if defined(_MSC_VER)
  #define COMPILER_MSVC
#elif defined(__clang__)
  #define COMPILER_CLANG
#elif defined(__GNUC__)
  #define COMPILER_GCC
#elif defined(__INTEL_COMPILER)
  #define COMPILER_INTEL
#elif defined(__MINGW32__)
  #define COMPILER_MINGW
#else
  #error "Unrecognized compiler."
#endif

}  // namespace app

#ifdef COMPILER_GCC
  #include <stdarg.h>
#endif

#include <stddef.h>
#include <stdint.h>
#include <string.h>

namespace app {

///////////////////////////////////////////////////////////////////////////////
// Macros
///////////////////////////////////////////////////////////////////////////////

#define Concatenate__(x, y) x##y
#define Concatenate_(x, y) Concatenate__(x, y)
#define Concatenate(x, y) Concatenate_(x, y)
#define UniqueIdentifier(name) Concatenate(_##name##_, __COUNTER__)

template <typename F>
struct Defer_RAII {
  F f;
  Defer_RAII(F f) : f(f) {}
  ~Defer_RAII() { f(); }
};
template <typename F>
Defer_RAII<F> defer_function(F f) {
  return Defer_RAII<F>(f);
}
#define Defer(code) auto UniqueIdentifier(defer) = defer_function([&]() { code; })

#define ArrayCount(a) (sizeof(a)/sizeof((a)[0]))

///////////////////////////////////////////////////////////////////////////////
// Utilities
///////////////////////////////////////////////////////////////////////////////

template <typename T>
T min(T const& a, T const& b) {
  return a < b ? a : b;
}
template <typename T>
T max(T const& a, T const& b) {
  return a > b ? a : b;
}

///////////////////////////////////////////////////////////////////////////////
// Array definition
///////////////////////////////////////////////////////////////////////////////

template <typename T>
struct Array {
  size_t count;
  T* address;

  inline T& operator[](const size_t idx) const {
    DR_ASSERT(idx < count);
    return address[idx];
  }

  class Iterator {
   public:
    using iterator_category = std::forward_iterator_tag;
    using value_type = T;
    using difference_type = ptrdiff_t;
    using pointer = T*;
    using reference = T&;

    Iterator(pointer ptr_) : ptr(ptr_) {}

    reference operator*() const { return *ptr; }
    pointer operator->() { return ptr; }

    inline Iterator& operator++() {
      ptr++;
      return *this;
    }

    // Postfix increment
    inline Iterator operator++(int) {
      Iterator tmp = *this;
      ++(*this);
      return tmp;
    }

    inline friend bool operator==(const Iterator& a, const Iterator& b) { return a.ptr == b.ptr; }
    inline friend bool operator!=(const Iterator& a, const Iterator& b) { return a.ptr != b.ptr; }

   private:
    pointer ptr;
  };

  // Functions to obtain iterators
  Iterator begin() const { return Iterator(address); }
  Iterator end() const { return Iterator(address + count); }
};

template <typename T>
constexpr bool is_array = false;
template <typename T>
constexpr bool is_array<Array<T>> = true;

template <typename T, typename E>
constexpr bool is_array_of = false;
template <typename E>
constexpr bool is_array_of<Array<E>, E> = true;

///////////////////////////////////////////////////////////////////////////////
// DynamoRIO utilities
///////////////////////////////////////////////////////////////////////////////

template <typename T, bool zero = true>
inline T* DrThreadAlloc(void* drcontext) {
  void* ptr = dr_thread_alloc(drcontext, sizeof(T));
  DR_ASSERT(ptr);
  if constexpr (zero) {
    memset(ptr, 0, sizeof(T));
  }
  return reinterpret_cast<T*>(ptr);
}

template <typename T>
inline void DrThreadFree(void* drcontext, T* ptr) {
  dr_thread_free(drcontext, reinterpret_cast<void*>(ptr), sizeof(T));
}
// Call DrThreadArrayFree instead!
template <typename T>
inline void DrThreadFree(void* context, Array<T>* ptr) = delete;

template <typename T, bool zero = true>
inline Array<T> DrThreadAllocArray(void* drcontext, size_t count) {
  void* ptr = nullptr;
  if (drcontext) {
    ptr = dr_thread_alloc(drcontext, sizeof(T) * count);
  } else {
    ptr = dr_global_alloc(sizeof(T) * count);
  }
  DR_ASSERT(ptr);
  if constexpr (zero) {
    memset(ptr, 0, sizeof(T) * count);
  }
  return {count, reinterpret_cast<T*>(ptr)};
}

template <typename T>
inline void DrThreadFreeArray(void* drcontext, Array<T>* array) {
  if (drcontext) {
    dr_thread_free(drcontext, reinterpret_cast<void*>(array->address), sizeof(T) * array->count);
  } else {
    dr_global_free(reinterpret_cast<void*>(array->address), sizeof(T) * array->count);
  }
  *array = {};
}

///////////////////////////////////////////////////////////////////////////////
// Array utilities
///////////////////////////////////////////////////////////////////////////////

template <typename T>
inline Array<uint8_t> AsBytes(T* value) {
  return {sizeof(T), reinterpret_cast<uint8_t*>(value)};
}

template <typename T, typename... Arrays>
  requires(is_array_of<Arrays, T> && ...)
Array<T> ConcatenateArrays(void* drcontext, const Array<T>& first, const Arrays&... rest) {
  size_t totalCount = (first.count + ... + rest.count);
  Array<T> result = DrThreadAllocArray<T>(drcontext, totalCount);

  size_t cursor = 0;
  auto copy = [&result, &cursor](const auto& array) {
    memcpy(result.address + cursor, array.address, array.count * sizeof(T));
    cursor += array.count;
  };

  copy(first);
  (copy(rest), ...);

  return result;
}

///////////////////////////////////////////////////////////////////////////////
// String
///////////////////////////////////////////////////////////////////////////////

using String = Array<uint8_t>;

#define StringArgs(string) static_cast<int>((string).count), reinterpret_cast<char*>((string).address)

bool IsWhitespace(uint8_t character);

static inline String Wrap(const char* cStr) {
  return {cStr ? strlen(cStr) : 0, reinterpret_cast<uint8_t*>(const_cast<char*>(cStr))};
}

// Always returns a zero-terminated string.
static String Allocate(void* drcontext, const char* cStr);
static String Allocate(void* drcontext, String string);
static String Allocate(void* drcontext, String string);

String Substring(String string, size_t start_index, size_t length);

bool operator==(String lhs, String rhs);
bool operator==(String lhs, const char* rhs);
bool operator==(const char* lhs, String rhs);

inline bool operator!=(String lhs, String rhs) { return !(lhs == rhs); }
inline bool operator!=(String lhs, const char* rhs) { return !(lhs == rhs); }
inline bool operator!=(const char* lhs, String rhs) { return !(lhs == rhs); }

bool PrefixEquals(String string, String prefix);
bool SuffixEquals(String string, String suffix);
bool CompareCaseInsensitive(const void* m1, const void* m2, size_t length);
bool CompareCaseInsensitive(String lhs, String rhs);
bool PrefixEqualsCaseInsensitive(String string, String prefix);
bool SuffixEqualsCaseInsensitive(String string, String suffix);

constexpr size_t kNotFound = ~(size_t)0;

size_t FindFirstOccurance(String string, uint8_t of);
size_t FindFirstOccurance(String string, String of);
size_t FindFirstOccuranceOfAny(String string, String anyOf);
inline size_t FindFirstOccurance(String string, char of) { return FindFirstOccurance(string, (uint8_t)of); }

String Consume(String string, size_t amount = 1);
void Consume(String* string, size_t amount);
String Take(String* string, size_t amount);
void ConsumeWhitespace(String* string);

static String ConsumeLine(String* string);
static String ConsumeLinePreserveWhitespace(String* string);
static String ConsumeUntil(String* string, uint8_t UntilWhat);
static String ConsumeUntil(String* string, String UntilWhat);
static String ConsumeUntilPreserveWhitespace(String* string, String UntilWhat);
static String ConsumeUntilAny(String* string, String UntilAnyOf);
static String ConsumeUntilWhitespace(String* string);
static String ConsumeUntilLast(String* string, uint8_t UntilWhat);
static String ConsumeUntilLast(String* string, String UntilWhat);
static String Trim(String string);
static String TrimFront(String string);
static String TrimBack(String string);

///////////////////////////////////////////////////////////////////////////////
// Filesystem
///////////////////////////////////////////////////////////////////////////////

struct BufferedFileWriter {
  void* drcontext;
  file_t file;
  Array<uint8_t> buffer;
  size_t cursor;

  static void Make(BufferedFileWriter* writer, void* drcontext, file_t file, size_t bufferSize);

  void FlushAndDestroy();

  void EnsureBufferSize(size_t size);

  inline void Write(Array<uint8_t> data) {
    EnsureBufferSize(data.count);
    memcpy(buffer.address + cursor, data.address, data.count);
    cursor += data.count;
  }

  // We only support LE architectures.
  inline void WriteUint8LE(uint8_t value) { Write(AsBytes(&value)); }
  inline void WriteUint16LE(uint16_t value) { Write(AsBytes(&value)); }
  inline void WriteUint32LE(uint32_t value) { Write(AsBytes(&value)); }
  inline void WriteUint64LE(uint64_t value) { Write(AsBytes(&value)); }

  void WriteString(String string);
};

struct BufferedFileReader {
  void* drcontext;
  file_t file;
  uint64_t fileSize;
  uint64_t fileCursor;

  Array<uint8_t> buffer;
  size_t bufferCursor;
  size_t bufferFilledTo;

  static void Make(BufferedFileReader* reader, void* drcontext, file_t file, size_t bufferSize);

  void Destroy();

  bool Read(Array<uint8_t> const& data);

  // We only support LE architectures.
  inline bool ReadUint8LE(uint8_t* value) {
    *value = 0;
    return Read(AsBytes(value));
  }
  inline bool ReadUint16LE(uint16_t* value) {
    *value = 0;
    return Read(AsBytes(value));
  }
  inline bool ReadUint32LE(uint32_t* value) {
    *value = 0;
    return Read(AsBytes(value));
  }
  inline bool ReadUint64LE(uint64_t* value) {
    *value = 0;
    return Read(AsBytes(value));
  }

  bool ReadString(void* drcontext, String* string);
};

file_t OpenUniqueFile(String directory, String nameBase, String extension, bool read, bool write);

}  // namespace app
