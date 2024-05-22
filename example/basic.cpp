#include <atomic>
#include <thread>
#include <cassert>
#include <iostream>
#include "test_tools.h"

std::atomic<int> x{0};

void test() {
  int thread_id = RegisterThread();
  while (Testing()) {
    if (thread_id == 0) {
      x = 0;
    }

    RunStart();

    int tmp1 = x.load(std::memory_order_seq_cst);
    x.store(tmp1 + 1, std::memory_order_seq_cst);

    int tmp2 = x.load(std::memory_order_seq_cst);
    x.store(tmp2 - 1, std::memory_order_seq_cst);

    int tmp3 = x.load(std::memory_order_seq_cst);

    AssertAlways(tmp3 == 0);
    RunEnd();
  }
}

int main() {
  std::cout << "HELLO FROM APP" << std::endl;

  std::thread t1(test);
  std::thread t2(test);

  t1.join();
  t2.join();

  return 0;
}
