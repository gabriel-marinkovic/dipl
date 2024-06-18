#include <cstdint>
#include <thread>
#include <boost/lockfree/stack.hpp>
#include "test_tools.h"

constexpr int QSIZE = 2;
using StackT = boost::lockfree::stack<uint32_t>;

void producer(StackT& s) {
  int thread_id = RegisterThread(0);

  while (Testing()) {
    s.~StackT();
    new (&s) StackT(QSIZE);

    RunStart();
    ContiguousMemoryHint(&s, sizeof(s));

    bool push1 = s.push(PreventOpt(1));
    bool push2 = s.push(PreventOpt(2));
    bool push3 = s.push(PreventOpt(3));

    AssertAlways(push1 && push2);
    AssertAtleastOnce(0, !push3);
    AssertAtleastOnce(1, push3);
    RunEnd();
  }
}

void consumer(StackT& s) {
  int thread_id = RegisterThread(1);

  while (Testing()) {
    RunStart();

    bool ok = true;
    uint32_t value = 0xff;
    bool popped;

    popped = s.pop(value);
    ok = ok && (!popped || (value != 0 && value <= 3));

    popped = s.pop(value);
    ok = ok && (!popped || (value != 0 && value <= 2));

    popped = s.pop(value);
    ok = ok && (!popped || (value != 0 && value == 1));

    AssertAlways(ok);
    AssertAtleastOnce(2, !popped);
    AssertAtleastOnce(3, popped && value == 1);
    RunEnd();
  }
}

int main() {
  StackT s(QSIZE);  // Initialize the stack with a fixed size
  std::thread t1(producer, std::ref(s));
  std::thread t2(consumer, std::ref(s));

  t1.join();
  t2.join();
  return 0;
}
