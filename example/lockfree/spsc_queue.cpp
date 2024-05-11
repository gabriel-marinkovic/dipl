#include <cstdint>
#include <thread>
#include <stdio.h>
#include "lockfree.hpp"


bool volatile bool_sink_prevent_optimization;
int volatile int_sink_prevent_optimization;
bool volatile true_literal_prevent_optimization = true;
bool volatile false_literal_prevent_optimization = false;
int volatile one_literal_prevent_optimization = 1;

extern "C" bool __attribute__((noinline)) NextRun() {
  __asm__ __volatile__("");
  return false_literal_prevent_optimization;
}

extern "C" bool __attribute__((noinline)) Initializing() {
  __asm__ __volatile__("");
  return false_literal_prevent_optimization;
}

extern "C" int __attribute__((noinline)) RepeatDuringCollection(int n) {
  __asm__ __volatile__("");
  int_sink_prevent_optimization = n;
  return one_literal_prevent_optimization;
}

extern "C" void __attribute__((noinline)) ReportTestResult(bool ok) {
  __asm__ __volatile__("");
  bool_sink_prevent_optimization = ok;
}


using QueueT = lockfree::spsc::Queue<uint32_t, 128U>;

std::atomic<bool> done_producing;

void producer(QueueT& q) {
  while (NextRun()) {
    if (Initializing()) {
      q.~QueueT();
      new (&q) QueueT();
      done_producing.store(false, std::memory_order_seq_cst);
    }

    bool ok = q.Push(12345);
    done_producing.store(true, std::memory_order_release);

    ReportTestResult(ok);
  }
}

void consumer(QueueT& q) {
  while (NextRun()) {
    if (Initializing()) {
      q.~QueueT();
      new (&q) QueueT();
      done_producing.store(false, std::memory_order_seq_cst);
    }

    bool done = done_producing.load(std::memory_order_acquire);
    uint32_t value = 0xbeef;
    bool read = q.Pop(value);
    bool ok = (read && value == 12345) || (!done && !read);
    ReportTestResult(ok);
  }
}

int main() {
  lockfree::spsc::Queue<uint32_t, 128U> q;
  std::thread t1(producer, std::ref(q));
  std::thread t2(consumer, std::ref(q));

  t1.join();
  t2.join();
  return 0;
}
