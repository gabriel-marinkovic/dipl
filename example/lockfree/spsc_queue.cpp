#include <cstdint>
#include <thread>
#include <stdio.h>
#include "test_tools.h"
#include "lockfree.hpp"

using QueueT = lockfree::spsc::Queue<uint32_t, 128U>;

std::atomic<bool> done_producing;

void producer(QueueT& q) {
  while (NextRun()) {
    if (ThreadIdx() == 0) {
      q.~QueueT();
      new (&q) QueueT();
      done_producing.store(false, std::memory_order_seq_cst);
    }

    bool ok = q.Push(12345);
    done_producing.store(true, std::memory_order_release);

    MustAlways(ok);
  }
}

void consumer(QueueT& q) {
  while (NextRun()) {
    if (ThreadIdx() == 0) {
      q.~QueueT();
      new (&q) QueueT();
      done_producing.store(false, std::memory_order_seq_cst);
    }

    bool done = done_producing.load(std::memory_order_acquire);
    uint32_t value = 0xbeef;
    bool read = q.Pop(value);
    bool ok = (read && value == 12345) || (!done && !read);
    MustAlways(ok);
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
