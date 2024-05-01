#include <mutex>
#include <thread>
#include <cassert>
#include <iostream>

extern "C" void __attribute__((noinline)) BeginInstrumentation() { __asm__ __volatile__(""); }
extern "C" void __attribute__((noinline)) EndInstrumentation() { __asm__ __volatile__(""); }

std::mutex mutex;
volatile int x = 0;
void test() {
  BeginInstrumentation();
  {
    std::unique_lock lock(mutex);
    x = x + 1;
  }
  EndInstrumentation();
}

int main() {
  std::thread t1(test);
  std::thread t2(test);

  t1.join();
  t2.join();

  if (x != 2) {
    std::cout << "FATAL ERROR IN `basic`!!!" << std::endl;
  }

  return 0;
}
