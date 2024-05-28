#include <cstdint>
#include <thread>
#include <stdio.h>
#include "test_tools.h"
#include "lockfree.hpp"

constexpr int QSIZE = 3;
using QueueT = lockfree::spsc::Queue<uint32_t, QSIZE>;

void producer(QueueT& q) {
  int thread_id = RegisterThread(0);
  ContiguousMemoryHint(&q, sizeof(q));

  while (Testing()) {
    q.~QueueT();
    new (&q) QueueT();

    RunStart();

    bool push1 = q.Push(PreventOpt(1));
    bool push2 = q.Push(PreventOpt(2));
    bool push3 = q.Push(PreventOpt(3));

    AssertAlways(push1 && push2);
    AssertAtleastOnce(0, !push3);
    AssertAtleastOnce(1, push3);
    RunEnd();
  }
}

void consumer(QueueT& q) {
  int thread_id = RegisterThread(1);

  while (Testing()) {
    RunStart();

    bool ok = true;
    uint32_t value = 0xff;
    bool popped;

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value == 1));

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 2));

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 3));

    AssertAlways(ok);
    AssertAtleastOnce(3, !popped);
    AssertAtleastOnce(3, popped && value == 3);
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
