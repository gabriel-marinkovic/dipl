#include <atomic>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

extern "C" void BeginInstrumentation() {}
extern "C" void EndInstrumentation() {}

extern volatile int writeMe = 0;
extern volatile int readMe = 0;

std::vector<uint64_t> globalData;

std::atomic<uint32_t> isInitialized{false};
std::mutex mutex;

void InitializeOnce(int dummy) {
  if (!isInitialized.load(std::memory_order_acquire)) {
    std::unique_lock lock(mutex);
    if (!isInitialized.load(std::memory_order_relaxed)) {
      for (uint64_t i = 1; i <= 10; ++i) {
        globalData.push_back(i * i + dummy);
      }
      isInitialized.store(1, std::memory_order_release);
    }
  }
}

void ThreadFunction() {
  BeginInstrumentation();

  InitializeOnce(readMe);
  for (auto x : globalData) {
    writeMe = x;
  }

  EndInstrumentation();
}

int main() {
  std::thread t1(ThreadFunction);
  std::thread t2(ThreadFunction);

  t1.join();
  t2.join();

  return 0;
}
