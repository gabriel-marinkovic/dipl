#include <atomic>
#include <cassert>
#include <iostream>
#include <thread>

#include <linux/futex.h>
#include <sys/syscall.h>
#include <unistd.h>

bool volatile bool_sink_prevent_optimization;
int volatile int_sink_prevent_optimization;
bool volatile false_literal_prevent_optimization = false;
int volatile one_literal_prevent_optimization = 1;

extern "C" bool __attribute__((noinline)) NextRun() {
  __asm__ __volatile__("");
  return false_literal_prevent_optimization;
}

extern "C" bool __attribute__((noinline)) Initializing() {
  __asm__ __volatile__("");
  return false_literal_prevent_optimization;
}

extern "C" int __attribute__((noinline)) RepeatDuringCollection(int n) {
  __asm__ __volatile__("");
  int_sink_prevent_optimization = n;
  return one_literal_prevent_optimization;
}

extern "C" void __attribute__((noinline)) ReportTestResult(bool ok) {
  __asm__ __volatile__("");
  bool_sink_prevent_optimization = ok;
}

bool wait_on_address(std::atomic<uint32_t>* address, uint32_t expected_value) {
  int* addr_as_int = reinterpret_cast<int*>(address);
  int ret = syscall(SYS_futex, addr_as_int, FUTEX_WAIT, expected_value, nullptr, nullptr, 0);
  if (ret == -1 && errno == ETIMEDOUT) {
    return false;
  }
  return ret != -1;
}

void notify_address_all(std::atomic<uint32_t>* address) {
  int* addr_as_int = reinterpret_cast<int*>(address);
  syscall(SYS_futex, addr_as_int, FUTEX_WAKE, INT_MAX);
}

struct FairLock {
  std::atomic<uint32_t> next_ticket{0};
  std::atomic<uint32_t> current_ticket{0};

  void acquire() {
    uint32_t ticket = next_ticket.fetch_add(1, std::memory_order_seq_cst);
  again:
    uint32_t current = current_ticket.load(std::memory_order_seq_cst);
    if (current != ticket) {
      wait_on_address(&current_ticket, current);
      goto again;
    }
  }

  void release() {
    current_ticket.fetch_add(1, std::memory_order_seq_cst);
    notify_address_all(&current_ticket);
  }
};

FairLock lock;
volatile int x;
void test() {
  while (NextRun() || true) {
    if (Initializing()) {
      lock.~FairLock();
      new (&lock) FairLock();
      x = 0;
    }

    for (int i = 0; i < RepeatDuringCollection(100); ++i) {
      lock.acquire();
      x = x + 1;
      x = x - 1;
      lock.release();
    }

    lock.acquire();
    int result = x;
    lock.release();

    ReportTestResult(result == 0);
    return;
  }
}

int main() {
  std::thread t1(test);
  std::thread t2(test);

  t1.join();
  t2.join();

  return 0;
}
