#include <stdio.h>
#include <cstdint>
#include <thread>
#include <ck_fifo.h>
#include "test_tools.h"

constexpr int QSIZE = 3;

struct QueueT {
  ck_fifo_spsc_t fifo;
  ck_fifo_spsc_entry_t stub;
  ck_fifo_spsc_entry_t entries[QSIZE];
};

void producer(QueueT& q) {
  int thread_id = RegisterThread(0);

  while (Testing()) {
    ck_fifo_spsc_entry_t* stub_ptr;
    ck_fifo_spsc_deinit(&q.fifo, &stub_ptr);
    bool stub_valid = stub_ptr == &q.stub;
    ck_fifo_spsc_init(&q.fifo, &q.stub);

    RunStart();
    ContiguousMemoryHint(&q, sizeof(q));

    ck_fifo_spsc_enqueue(&q.fifo, &q.entries[0], (void*)(uintptr_t)PreventOpt(1));
    ck_fifo_spsc_enqueue(&q.fifo, &q.entries[1], (void*)(uintptr_t)PreventOpt(2));
    ck_fifo_spsc_enqueue(&q.fifo, &q.entries[2], (void*)(uintptr_t)PreventOpt(3));

    AssertAlways(stub_valid);
    RunEnd();
  }
}

void consumer(QueueT& q) {
  int thread_id = RegisterThread(1);

  while (Testing()) {
    RunStart();

    bool ok = true;
    void* value_ptr = nullptr;
    bool popped;

    popped = ck_fifo_spsc_dequeue(&q.fifo, &value_ptr);
    uint32_t value = (uint32_t)(uintptr_t)value_ptr;
    ok = ok && (!popped || (value != 0 && value == 1));

    popped = ck_fifo_spsc_dequeue(&q.fifo, &value_ptr);
    value = (uint32_t)(uintptr_t)value_ptr;
    ok = ok && (!popped || (value != 0 && value <= 2));

    popped = ck_fifo_spsc_dequeue(&q.fifo, &value_ptr);
    value = (uint32_t)(uintptr_t)value_ptr;
    ok = ok && (!popped || (value != 0 && value <= 3));

    AssertAlways(ok);
    AssertAtleastOnce(2, !popped);
    AssertAtleastOnce(3, popped && value == 3);

    RunEnd();
  }
}

int main() {
  QueueT q;
  ck_fifo_spsc_init(&q.fifo, &q.stub);

  std::thread t1(producer, std::ref(q));
  std::thread t2(consumer, std::ref(q));

  t1.join();
  t2.join();

  return 0;
}
