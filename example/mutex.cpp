#include <mutex>
#include <thread>
#include <cassert>
#include <iostream>

bool volatile sink_prevent_optimization;
bool volatile false_literal_prevent_optimization = false;

extern "C" bool __attribute__((noinline)) Testing() {
  __asm__ __volatile__("");
  return false_literal_prevent_optimization;
}

extern "C" bool __attribute__((noinline)) Initializing() {
  __asm__ __volatile__("");
  return false_literal_prevent_optimization;
}

extern "C" void __attribute__((noinline)) ReportTestResult(bool ok) {
  __asm__ __volatile__("");
  sink_prevent_optimization = ok;
}

std::mutex mutex;
volatile int x;
void test() {
  while (Testing()) {
    if (Initializing()) {
      mutex.~mutex();
      new(&mutex) std::mutex();
      x = 0;
    }

    {
      std::unique_lock lock(mutex);
      x = x + 1;
      x = x - 1;
    }

    ReportTestResult(x == 0);
  }
}

int main() {
  std::thread t1(test);
  std::thread t2(test);

  t1.join();
  t2.join();

  return 0;
}
