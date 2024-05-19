#include <cstdint>
#include <thread>
#include <stdio.h>
#include "test_tools.h"
#include "lockfree.hpp"

constexpr int QSIZE = 3;
using QueueT = lockfree::spsc::Queue<uint32_t, QSIZE>;

void producer(QueueT& q) {
  int thread_id = RegisterThread(0);

  while (NextRun()) {
    ContiguousMemoryHint(&q, sizeof(q));

    if (thread_id == 0) {
      q.~QueueT();
      new (&q) QueueT();
    }

    bool pushed;
    pushed = q.Push(PreventOpt(1));
    pushed = q.Push(PreventOpt(2));
    pushed = q.Push(PreventOpt(3));
    pushed = q.Push(PreventOpt(4));

    MustAlways(true);
    MustAtleastOnce(0, !pushed);
    MustAtleastOnce(1, pushed);
    RunDone();
  }
}

void consumer(QueueT& q) {
  int thread_id = RegisterThread(1);

  while (NextRun()) {
    ContiguousMemoryHint(&q, sizeof(q));

    if (thread_id == 0) {
      q.~QueueT();
      new (&q) QueueT();
    }

    bool ok = true;
    uint32_t value = 0xff;
    bool popped;

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value == 1));

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 2));

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 3));

    MustAlways(ok);
    MustAtleastOnce(2, popped && value == 3);
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
