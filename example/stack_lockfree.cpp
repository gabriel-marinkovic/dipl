#include <atomic>
#include <cassert>
#include <iostream>
#include <thread>
#include "test_tools.h"

struct Node {
  int value;
  Node* next;
};

static Node the_hacky_bump_allocator_memory[100];
static std::atomic<int> the_hacky_bump_allocator_next;

Node* HackyAllocateNode() {
  int idx = the_hacky_bump_allocator_next.fetch_add(1, std::memory_order_acquire);
  assert(idx < 100);
  the_hacky_bump_allocator_memory[idx] = {};
  return &the_hacky_bump_allocator_memory[idx];
}
void HackyFreeNode(Node*) {}

class LockfreeStack {
 private:
  std::atomic<Node*> head;

 public:
  LockfreeStack() : head(nullptr) {}

  ~LockfreeStack() {
    Node* current = head.load(std::memory_order_relaxed);
    while (current != nullptr) {
      Node* temp = current;
      current = current->next;
      HackyFreeNode(temp);
    }
  }

  bool Push(int value) {
    Node* node = HackyAllocateNode();
    node->value = value;
    node->next = nullptr;
    Node* old_head = head.load(std::memory_order_relaxed);
    do {
      node->next = old_head;
    } while (!head.compare_exchange_weak(old_head, node, std::memory_order_release, std::memory_order_relaxed));
    return true;
  }

  bool Pop(int* value = nullptr) {
    Node* old_head = head.load(std::memory_order_relaxed);
    while (old_head) {
      Node* next = old_head->next;
      if (head.compare_exchange_weak(old_head, next, std::memory_order_release, std::memory_order_relaxed)) {
        if (value) *value = old_head->value;
        HackyFreeNode(old_head);
        return true;
      }
    }
    return false;
  }
};

void test(LockfreeStack& stack) {
  while (NextRun()) {
    if (ThreadIdx() == 0) {
      stack.~LockfreeStack();
      new (&stack) LockfreeStack();
      the_hacky_bump_allocator_next.store(0, std::memory_order_seq_cst);
    }

    bool ok = true;
    ok = ok && stack.Push(5);

    int out;
    ok = ok && stack.Pop(&out);
    ok = ok && (out == 5);

    MustAlways(ok);
    RunDone();
  }
}

int main() {
  LockfreeStack stack;
  std::thread t1(test, std::ref(stack));
  std::thread t2(test, std::ref(stack));

  t1.join();
  t2.join();
  return 0;
}
