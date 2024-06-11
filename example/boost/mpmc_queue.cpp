#include <cstdint>
#include <thread>
#include <boost/lockfree/queue.hpp>
#include "test_tools.h"

constexpr int QSIZE = 1;
using QueueT = boost::lockfree::queue<uint32_t, boost::lockfree::capacity<QSIZE>>;

void producer(QueueT& q) {
  int thread_id = RegisterThread(0);

  while (Testing()) {
    q.~QueueT();
    new (&q) QueueT();

    RunStart();
    //ContiguousMemoryHint(&q, sizeof(q));

    bool push1 = q.push(PreventOpt(1));
    bool push2 = q.push(PreventOpt(2));

    AssertAlways(push1);
    AssertAtleastOnce(0, !push2);
    AssertAtleastOnce(1, push2);
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

    popped = q.pop(value);
    ok = ok && (!popped || (value != 0 && value == 1));

    popped = q.pop(value);
    ok = ok && (!popped || (value != 0 && value <= 2));

    AssertAlways(ok);
    AssertAtleastOnce(2, !popped);
    AssertAtleastOnce(3, popped && value == 2);
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
