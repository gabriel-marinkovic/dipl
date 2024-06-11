#include <stdio.h>
#include <cstdint>
#include <thread>
extern "C" {
#include "ck_hp_fifo.h"
#include "ck_hp.h"
}
#include "test_tools.h"

constexpr int QSIZE = 1;
constexpr int HP_DEGREE = 2; // Number of hazard pointers per thread

ck_hp_t hp_global;
struct QueueT {
  ck_hp_fifo_t fifo;
  ck_hp_fifo_entry_t stub;
  ck_hp_fifo_entry_t entries[QSIZE];
  ck_hp_record_t hp_record;
  void* hp_pointers[HP_DEGREE];
};

void producer(QueueT& q) {
  int thread_id = RegisterThread(0);

  while (Testing()) {
    ck_hp_unregister(&q.hp_record);
    ck_hp_register(&hp_global, &q.hp_record, q.hp_pointers);

    ck_hp_fifo_entry_t* stub_ptr;
    ck_hp_fifo_deinit(&q.fifo, &stub_ptr);
    bool stub_valid = stub_ptr == &q.stub;
    ck_hp_fifo_init(&q.fifo, &q.stub);

    RunStart();
    //ContiguousMemoryHint(&q, &q.entries[QSIZE - 1] - &q.fifo);

    ck_hp_fifo_enqueue_mpmc(&q.hp_record, &q.fifo, &q.entries[0], (void*)(uintptr_t)PreventOpt(1));

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
    ck_hp_fifo_entry_t* entry;

    entry = ck_hp_fifo_dequeue_mpmc(&q.hp_record, &q.fifo, &value_ptr);
    uint32_t value = (uint32_t)(uintptr_t)value_ptr;
    ok = ok && (entry == nullptr || (value != 0 && value == 1));

    AssertAlways(ok);
    RunEnd();
  }
}

int main() {
  QueueT q;
  ck_hp_fifo_init(&q.fifo, &q.stub);

  ck_hp_init(&hp_global, HP_DEGREE, 2, nullptr); // 2 threads, HP_DEGREE hazard pointers per thread
  ck_hp_register(&hp_global, &q.hp_record, q.hp_pointers);

  std::thread t1(producer, std::ref(q));
  std::thread t2(consumer, std::ref(q));

  t1.join();
  t2.join();

  // Unregister hazard pointer record
  ck_hp_unregister(&q.hp_record);

  return 0;
}
