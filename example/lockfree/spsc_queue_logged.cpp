#include <cstdint>
#include <thread>
#include <iostream>
#include "lockfree.hpp"
#include "test_tools.h"

constexpr int QSIZE = 4;
using QueueT = lockfree::spsc::Queue<uint32_t, QSIZE>;

void producer(QueueT& q) {
  int thread_id = RegisterThread(0);
  ContiguousMemoryHint(&q, sizeof(q));

  while (Testing()) {
    q.~QueueT();
    new (&q) QueueT();

    RunStart();

    bool pushed;
    pushed = q.Push(PreventOpt(1));
    NO_INSTR(std::cout << "push #1: " << pushed << std::endl);
    pushed = q.Push(PreventOpt(2));
    NO_INSTR(std::cout << "push #2: " << pushed << std::endl);
    pushed = q.Push(PreventOpt(3));
    NO_INSTR(std::cout << "push #3: " << pushed << std::endl);

    AssertAlways(pushed);
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
    NO_INSTR(std::cout << "consumer pop #1: " << popped << ", value: " << value << std::endl);

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 2));
    NO_INSTR(std::cout << "consumer pop #2: " << popped << ", value: " << value << std::endl);

    popped = q.Pop(value);
    ok = ok && (!popped || (value != 0 && value <= 3));
    NO_INSTR(std::cout << "consumer pop #3: " << popped << ", value: " << value << std::endl);

    AssertAlways(ok);
    AssertAtleastOnce(0, popped && value == 3);
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
