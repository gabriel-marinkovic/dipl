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

class Stack {
 private:
  Node* head;

 public:
  Stack() : head(nullptr) {}

  ~Stack() {
    while (head != nullptr) {
      Node* temp = head;
      head = head->next;
      HackyFreeNode(temp);
    }
  }

  inline bool __attribute__((noinline)) Push(int value) {
    Node* node = HackyAllocateNode();
    node->value = value;
    node->next = head;
    head = node;
    return true;
  }

  inline bool __attribute__((noinline)) Pop(int* value = nullptr) {
    if (head == nullptr) return false;
    Node* temp = head;
    if (value) *value = temp->value;
    head = head->next;
    HackyFreeNode(temp);
    return true;
  }

  bool __attribute__((noinline)) IsEmpty() { return head == nullptr; }
};

void test(Stack& stack) {
  int thread_id = RegisterThread();

  while (Testing()) {
    if (thread_id == 0) {
      stack.~Stack();
      new (&stack) Stack();
      the_hacky_bump_allocator_next.store(0, std::memory_order_seq_cst);
    }

    RunStart();

    bool ok = true;
    ok = ok && stack.Push(5);

    int out;
    ok = ok && stack.Pop(&out);
    ok = ok && (out == 5);

    AssertAlways(ok);
    RunEnd();
  }
}

int main() {
  Stack stack;
  std::thread t1(test, std::ref(stack));
  std::thread t2(test, std::ref(stack));

  t1.join();
  t2.join();
  return 0;
}
