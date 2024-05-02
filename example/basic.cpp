#include <atomic>
#include <thread>
#include <cassert>
#include <iostream>

volatile bool false_literal_prevent_optimization = false;

extern "C" bool __attribute__((noinline)) NextRun() {
  __asm__ __volatile__("");
  return false_literal_prevent_optimization;
}

extern "C" bool __attribute__((noinline)) Initializing() {
  __asm__ __volatile__("");
  return false_literal_prevent_optimization;
}

extern "C" void __attribute__((noinline)) ReportTestResult(bool ok) {
  __asm__ __volatile__("");
}

std::atomic<int> x{0};

// Plan:
// Leave `Initializing` for last
// 1) Rename Begin/End into `NextRun` and `ReportTestResult`
// 2) Wrap them

void test() {
  while (NextRun()) {
    if (Initializing()) {
      x = 0;
    }

    int tmp1 = x.load(std::memory_order_seq_cst);
    x.store(tmp1 + 1, std::memory_order_seq_cst);

    int tmp2 = x.load(std::memory_order_seq_cst);
    x.store(tmp2 - 1, std::memory_order_seq_cst);

    int tmp3 = x.load(std::memory_order_seq_cst);

    ReportTestResult(tmp3 == 0);
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
