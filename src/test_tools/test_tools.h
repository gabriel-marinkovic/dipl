#pragma once

#include <barrier>

#define TEST_TOOL_FUNCTION __attribute__((noinline, used))
#define FN_PRELUDE __asm__ __volatile__("" ::: "memory")

volatile bool prevent_optimization_literal_bool_false = false;
volatile int prevent_optimization_literal_int_minus_one = -1;
volatile bool prevent_optimization_sink_bool = false;

extern "C" {

bool TEST_TOOL_FUNCTION Instrumenting() {
  FN_PRELUDE;
  return prevent_optimization_literal_bool_false;
}

void TEST_TOOL_FUNCTION InstrumentationPause() {
  FN_PRELUDE;
}

void TEST_TOOL_FUNCTION InstrumentationResume() {
  FN_PRELUDE;
}

//static std::barrier barrier(2);
void TEST_TOOL_FUNCTION InstrumentingWaitForAll() {
  FN_PRELUDE;
  if (!Instrumenting()) return;
  InstrumentationPause();
  //barrier.arrive_and_wait();
  InstrumentationResume();
}

bool TEST_TOOL_FUNCTION NextRun() {
  FN_PRELUDE;
  return prevent_optimization_literal_bool_false;
}

void TEST_TOOL_FUNCTION RunDone() {
  FN_PRELUDE;
}

int TEST_TOOL_FUNCTION ThreadIdx() {
  FN_PRELUDE;
  return prevent_optimization_literal_int_minus_one;
}

void TEST_TOOL_FUNCTION MustAlways(bool ok) {
  FN_PRELUDE;
  prevent_optimization_sink_bool = ok;
}

void TEST_TOOL_FUNCTION MustAtleastOnce(bool ok) {
  FN_PRELUDE;
  prevent_optimization_sink_bool = ok;
}

}

