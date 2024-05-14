#include <cstdint>
#include <thread>
#include <stdio.h>
#include "test_tools.h"
#include "lockfree.hpp"

constexpr int QSIZE = 4;
using QueueT = lockfree::spsc::Queue<uint32_t, QSIZE>;

void producer(QueueT& q) {
  while (NextRun()) {
    ContiguousMemoryHint(&q, sizeof(q));

    if (ThreadIdx() == 0) {
      q.~QueueT();
      new (&q) QueueT();
    }

    q.Push(PreventOpt(1));
    q.Push(PreventOpt(2));
    q.Push(PreventOpt(3));
    q.Push(PreventOpt(4));

    //NO_INSTR(printf("TID %d: pushed: %d, done: %d\n", ok, done_producing.load(std::memory_order_seq_cst)));

    MustAlways(true);
    RunDone();
  }
}

void consumer(QueueT& q) {
  while (NextRun()) {
    ContiguousMemoryHint(&q, sizeof(q));

    if (ThreadIdx() == 0) {
      q.~QueueT();
      new (&q) QueueT();
    }

    bool ok = true;
    uint32_t value = 0xff;
    bool popped;

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value == 1));
    //NO_INSTR(printf("TID %d: POP 1: popped: %d, value: %u\n", ThreadIdx(), popped, value));

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 2));
    //NO_INSTR(printf("TID %d: POP 2: popped: %d, value: %u\n", ThreadIdx(), popped, value));

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 3));
    //NO_INSTR(printf("TID %d: POP 3: popped: %d, value: %u\n", ThreadIdx(), popped, value));

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 4));
    //NO_INSTR(printf("TID %d: POP 4: popped: %d, value: %u\n", ThreadIdx(), popped, value));

    //NO_INSTR(printf("TID %d: done: %d, read: %d, value: %d\n", done, read, value));

    MustAlways(ok);
    MustAtleastOnce(popped && value == 4);
    RunDone();
  }
}

int main() {
  QueueT q;
  std::thread t1(producer, std::ref(q));
  std::thread t2(consumer, std::ref(q));

  t1.join();
  t2.join();
  return 0;
}
