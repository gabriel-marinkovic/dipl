#include <stdio.h>
#include <cstdint>
#include <thread>
#include "lockfree.hpp"
#include "test_tools.h"

constexpr int QSIZE = 3;
using QueueT = lockfree::spsc::Queue<uint32_t, QSIZE>;

void producer(QueueT& q) {
  int thread_id = RegisterThread(0);

  while (Testing()) {
    ContiguousMemoryHint(&q, sizeof(q));

    if (thread_id == 0) {
      q.~QueueT();
      new (&q) QueueT();
      NO_INSTR(printf("producer cleared\n"));
    }

    bool pushed;
    pushed = q.Push(PreventOpt(1));
    NO_INSTR(printf("pushed 1: %d\n", (int)pushed));
    pushed = q.Push(PreventOpt(2));
    NO_INSTR(printf("pushed 2: %d\n", (int)pushed));
    pushed = q.Push(PreventOpt(3));
    NO_INSTR(printf("pushed 3: %d\n", (int)pushed));
    pushed = q.Push(PreventOpt(4));
    NO_INSTR(printf("pushed 4: %d\n", (int)pushed));

    AssertAlways(true);
    AssertAtleastOnce(0, !pushed);
    AssertAtleastOnce(1, pushed);
    RunEnd();
  }
}

void consumer(QueueT& q) {
  int thread_id = RegisterThread(1);

  while (Testing()) {
    ContiguousMemoryHint(&q, sizeof(q));

    if (thread_id == 0) {
      q.~QueueT();
      new (&q) QueueT();
      NO_INSTR(printf("consumer cleared\n"));
    }

    bool ok = true;
    uint32_t value = 0xff;
    bool popped;

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value == 1));
    NO_INSTR(printf("consumer pop 1, %d, value %u\n", popped, value));

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 2));
    NO_INSTR(printf("consumer pop 2, %d, value %u\n", popped, value));

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 3));
    NO_INSTR(printf("consumer pop 3, %d, value %u\n", popped, value));

    AssertAlways(ok);
    AssertAtleastOnce(2, popped && value == 3);
    RunEnd();
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
