#include <atomic>
#include <thread>
#include <cassert>
#include <iostream>
#include "test_tools.h"

std::atomic<int> x{0};

void test() {
  while (NextRun()) {
    if (ThreadIdx() == 0) {
      x = 0;
    }

    x.fetch_add(1, std::memory_order_seq_cst);
    x.fetch_add(-1, std::memory_order_seq_cst);

    volatile int tmp3 = x.load(std::memory_order_seq_cst);
    MustAlways(tmp3 >= 0);
    MustAtleastOnce(0, tmp3 == 0);
    RunDone();
  }
}

int main() {
  std::thread t1(test);
  std::thread t2(test);

  t1.join();
  t2.join();

  return 0;
}
