#include <atomic>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

std::vector<uint64_t> globalData;

std::atomic<uint32_t> isInitialized{false};
std::mutex mutex;

void InitializeOnce() {
  if (!isInitialized.load(std::memory_order_acquire)) {
    std::unique_lock lock(mutex);
    if (!isInitialized.load(std::memory_order_relaxed)) {
      for (uint64_t i = 1; i <= 10; ++i) {
        globalData.push_back(i * i);
      }
      isInitialized.store(1, std::memory_order_release);
    }
  }
}

extern "C" void __attribute__((noinline)) BeginInstrumentation() {__asm__ __volatile__(""); }
extern "C" void __attribute__((noinline)) EndInstrumentation() { __asm__ __volatile__(""); }

void ThreadFunction() {
  printf("A thread is starting!\n");

  BeginInstrumentation();
  InitializeOnce();
  EndInstrumentation();
}

int main() {
  printf("Starting!\n");
  std::thread t1(ThreadFunction);
  std::thread t2(ThreadFunction);

  t1.join();
  t2.join();

  std::cout << "Done! " << isInitialized.load(std::memory_order_relaxed) << std::endl;
  for (auto x : globalData) {
    std::cout << x << std::endl;
  }
  return 0;
}
