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

///////////////////////////////////////////////////////////////////////////////
// Utilities
///////////////////////////////////////////////////////////////////////////////

template<typename T> T min(T const& a, T const& b) { return a < b ? a : b; }
template<typename T> T max(T const& a, T const& b) { return a > b ? a : b; }

///////////////////////////////////////////////////////////////////////////////
// Array
///////////////////////////////////////////////////////////////////////////////

template <typename T>
struct Array {
  size_t count;
  T* address;
};

template <typename T>
inline Array<uint8_t> AsBytes(T* value) {
  return {sizeof(T), reinterpret_cast<uint8_t*>(value)};
}

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
  inline bool ReadUint8LE(uint8_t* value) { *value = 0; return Read(AsBytes(value)); }
  inline bool ReadUint16LE(uint16_t* value) { *value = 0; return Read(AsBytes(value)); }
  inline bool ReadUint32LE(uint32_t* value) { *value = 0; return Read(AsBytes(value)); }
  inline bool ReadUint64LE(uint64_t* value) { *value = 0; return Read(AsBytes(value)); }
};

///////////////////////////////////////////////////////////////////////////////
// DynamoRIO utilities
///////////////////////////////////////////////////////////////////////////////

template<typename T, bool zero = true>
inline T* DrThreadAlloc(void* drcontext) {
	void* ptr = dr_thread_alloc(drcontext, sizeof(T));
	DR_ASSERT(ptr);
	if constexpr (zero) {
		memset(ptr, 0, sizeof(T));
	}
	return reinterpret_cast<T*>(ptr);
}

template<typename T>
inline void DrThreadFree(void* drcontext, T* ptr) {
	dr_thread_free(drcontext, reinterpret_cast<void*>(ptr), sizeof(T));
}
// Call DrThreadArrayFree instead!
template<typename T>
inline void DrThreadFree(void* context, Array<T>* ptr) = delete;

template<typename T, bool zero = true>
inline Array<T> DrThreadAllocArray(void* drcontext, size_t count) {
	void* ptr = dr_thread_alloc(drcontext, sizeof(T) * count);
	DR_ASSERT(ptr);
	if constexpr (zero) {
		memset(ptr, 0, sizeof(T) * count);
	}
	return {count, reinterpret_cast<T*>(ptr)};
}

template<typename T>
inline void DrThreadFreeArray(void* drcontext, Array<T>* array) {
	dr_thread_free(drcontext, reinterpret_cast<void*>(array->address), sizeof(T) * array->count);
	*array = {};
}


}  // namespace app
