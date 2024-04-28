#include <atomic>
#include <thread>
#include <cassert>
#include <iostream>
#include <latch>

extern "C" void __attribute__((noinline)) BeginInstrumentation() {__asm__ __volatile__(""); }
extern "C" void __attribute__((noinline)) EndInstrumentation() { __asm__ __volatile__(""); }

std::latch wait_for_both{2};

std::atomic<int> x{0};
void test() {
  wait_for_both.count_down();
  wait_for_both.wait();

  BeginInstrumentation();

  int tmp1 = x.load(std::memory_order_seq_cst);
  x.store(tmp1 + 1, std::memory_order_seq_cst);

  int tmp2 = x.load(std::memory_order_seq_cst);
  x.store(tmp2 - 1, std::memory_order_seq_cst);

  int tmp3 = x.load(std::memory_order_seq_cst);

  EndInstrumentation();

  if (tmp3 != 0) {
    std::cout << "FATAL ERROR IN `basic`!!!" << std::endl;
  }
}

int main() {
  std::thread t1(test);
  std::thread t2(test);

  t1.join();
  t2.join();

  return 0;
}
