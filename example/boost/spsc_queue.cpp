#include <cstdint>
#include <thread>
#include <boost/lockfree/spsc_queue.hpp>
#include "test_tools.h"

constexpr int QSIZE = 2;
using QueueT = boost::lockfree::spsc_queue<uint32_t, boost::lockfree::capacity<QSIZE>>;

void producer(QueueT& q) {
  int thread_id = RegisterThread(0);

  while (Testing()) {
    q.reset();  // Reset the queue for a new test run

    RunStart();
    ContiguousMemoryHint(&q, sizeof(q));

    bool push1 = q.push(PreventOpt(1));
    bool push2 = q.push(PreventOpt(2));
    bool push3 = q.push(PreventOpt(3));

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

    popped = q.pop(value);
    ok = ok && (!popped || (value != 0 && value == 1));

    popped = q.pop(value);
    ok = ok && (!popped || (value != 0 && value <= 2));

    popped = q.pop(value);
    ok = ok && (!popped || (value != 0 && value <= 3));

    AssertAlways(ok);
    AssertAtleastOnce(2, !popped);
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
