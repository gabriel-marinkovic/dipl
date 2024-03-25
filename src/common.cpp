#include "dr_api.h"
#include "dr_tools.h"

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
// Filesystem
///////////////////////////////////////////////////////////////////////////////

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
