#include <atomic>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <thread>
#include <utility>
#include <vector>

//std::vector<uint64_t> globalData;

std::atomic<uint32_t> isInitialized{false};
std::mutex mutex;

void InitializeOnce() {
  if (!isInitialized.load(std::memory_order_acquire)) {
    std::unique_lock lock(mutex);
    if (!isInitialized.load(std::memory_order_relaxed)) {
      //for (uint64_t i = 1; i <= 10; ++i) {
      //  globalData.push_back(i * i);
      //}
      isInitialized.store(1, std::memory_order_release);
      //std::cout << "Global data initialized by thread: " << std::this_thread::get_id() << std::endl;
    }
  }
}

void ThreadFunction() {
  InitializeOnce();
  //std::cout << "Thread " << std::this_thread::get_id() << " sees globalData:";
  //for (auto x : globalData) {
  //  //std::cout << " " << x;
  //}
  //std::cout << std::endl;
}

int main() {
  std::thread t1(ThreadFunction);
  std::thread t2(ThreadFunction);

  t1.join();
  t2.join();

  return 0;
}
