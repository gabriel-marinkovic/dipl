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

    x.fetch_add(1, std::memory_order_seq_cst);
    x.fetch_add(-1, std::memory_order_seq_cst);

    volatile int tmp3 = x.load(std::memory_order_seq_cst);
    AssertAlways(tmp3 >= 0);
    AssertAtleastOnce(0, tmp3 == 0);
    RunEnd();
  }
}

int main() {
  std::thread t1(test);
  std::thread t2(test);

  t1.join();
  t2.join();

  return 0;
}
