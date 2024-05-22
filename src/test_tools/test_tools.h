#pragma once

#include <barrier>

#define TEST_TOOL_FUNCTION __attribute__((noinline, used))
#define FN_PRELUDE __asm__ __volatile__("" ::: "memory")

volatile bool prevent_optimization_literal_bool_false = false;
volatile int prevent_optimization_literal_int_minus_one = -1;
volatile bool prevent_optimization_sink_bool;
volatile int prevent_optimization_sink_int;
volatile void* prevent_optimization_sink_voidptr;

extern "C" {

bool TEST_TOOL_FUNCTION Instrumenting() {
  FN_PRELUDE;
  return prevent_optimization_literal_bool_false;
}

void TEST_TOOL_FUNCTION InstrumentationPause() { FN_PRELUDE; }

void TEST_TOOL_FUNCTION InstrumentationResume() { FN_PRELUDE; }

static std::barrier barrier(2);
void TEST_TOOL_FUNCTION InstrumentingWaitForAll() {
  FN_PRELUDE;
  if (!Instrumenting()) return;
  InstrumentationPause();
  barrier.arrive_and_wait();
  InstrumentationResume();
}

int TEST_TOOL_FUNCTION RegisterThread(int preferred_thread_id = -1) {
  FN_PRELUDE;
  volatile int prevent_optimization_thread_id = preferred_thread_id;
  return prevent_optimization_thread_id;
}

bool TEST_TOOL_FUNCTION Testing() {
  FN_PRELUDE;
  return prevent_optimization_literal_bool_false;
}

void TEST_TOOL_FUNCTION RunStart() { FN_PRELUDE; }

void TEST_TOOL_FUNCTION RunEnd() { FN_PRELUDE; }

void TEST_TOOL_FUNCTION AssertAlways(bool ok) {
  FN_PRELUDE;
  prevent_optimization_sink_bool = ok;
}

void TEST_TOOL_FUNCTION AssertAtleastOnce(int condition_idx, bool ok) {
  FN_PRELUDE;
  prevent_optimization_sink_int = condition_idx;
  prevent_optimization_sink_bool = ok;
}

void TEST_TOOL_FUNCTION ContiguousMemoryHint(void* ptr, int size) {
  FN_PRELUDE;
  prevent_optimization_sink_voidptr = ptr;
  prevent_optimization_sink_int = size;
}

#define NO_INSTR(code)      \
  do {                      \
    if (!Instrumenting()) { \
      code;                 \
    }                       \
  } while (0)
}

template <typename T>
T TEST_TOOL_FUNCTION PreventOpt(T x) {
  FN_PRELUDE;
  volatile T volatile_t = x;
  return volatile_t;
}
