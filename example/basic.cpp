#include <atomic>
#include <thread>
#include <cassert>

extern "C" void __attribute__((noinline)) BeginInstrumentation() {__asm__ __volatile__(""); }
extern "C" void __attribute__((noinline)) EndInstrumentation() { __asm__ __volatile__(""); }

std::atomic<int> x{0};
void test() {
  int tmp1 = x.load(std::memory_order_seq_cst);
  x.store(tmp1 + 1, std::memory_order_seq_cst);

  int tmp2 = x.load(std::memory_order_seq_cst);
  x.store(tmp2 - 1, std::memory_order_seq_cst);

  int tmp3 = x.load(std::memory_order_seq_cst);
  assert(tmp3 == 0);
}

void ThreadEntry() {
  BeginInstrumentation();
  test();
  EndInstrumentation();
}

int main() {
  std::thread t1(ThreadEntry);
  std::thread t2(ThreadEntry);

  t1.join();
  t2.join();

  return 0;
}
