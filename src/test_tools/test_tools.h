#pragma once

#define TEST_TOOL_FUNCTION __attribute__((noinline, used))
#define COMPILER_FENCE __asm__ __volatile__("" ::: "memory")

#define FENCE_WRAPPER(return_type, expr)     \
  (__extension__({                           \
    COMPILER_FENCE;                          \
    return_type __ret = (return_type)(expr); \
    COMPILER_FENCE;                          \
    __ret;                                   \
  }))
#define FENCE_WRAPPER_VOID(expr) \
  (__extension__({               \
    COMPILER_FENCE;              \
    (expr);                      \
    COMPILER_FENCE;              \
  }))

// clang-format off
#define ASM_STUB(function_name)  \
__asm__(                         \
  ".global " #function_name "\n" \
  #function_name ":\n"           \
  "  ret\n")
// clang-format on

#define NO_INSTR(code)      \
  do {                      \
    if (!Instrumenting()) { \
      code;                 \
      COMPILER_FENCE;       \
    }                       \
  } while (0)

#define TRACE(code)   \
  do {                \
    if (Tracing()) {  \
      code;           \
      COMPILER_FENCE; \
    }                 \
  } while (0)

template <typename T>
T TEST_TOOL_FUNCTION PreventOpt(T x) {
  COMPILER_FENCE;
  volatile T volatile_t = x;
  return volatile_t;
  COMPILER_FENCE;
}

extern "C" {

extern bool TEST_TOOL_FUNCTION _Tracing();
extern bool TEST_TOOL_FUNCTION _Instrumenting();
extern void TEST_TOOL_FUNCTION _InstrumentationPause();
extern void TEST_TOOL_FUNCTION _InstrumentationResume();
extern int TEST_TOOL_FUNCTION _RegisterThread(int preferred_thread_id = -1);
extern bool TEST_TOOL_FUNCTION _Testing();
extern void TEST_TOOL_FUNCTION _RunStart();
extern void TEST_TOOL_FUNCTION _RunEnd();
extern void TEST_TOOL_FUNCTION _AssertAlways(bool ok);
extern void TEST_TOOL_FUNCTION _AssertAtleastOnce(int condition_idx, bool ok);
extern void TEST_TOOL_FUNCTION _ContiguousMemoryHint(void* ptr, int size);

// clang-format off
#define Tracing(...)               FENCE_WRAPPER(bool, _Tracing(__VA_ARGS__))
#define Instrumenting(...)         FENCE_WRAPPER(bool, _Instrumenting(__VA_ARGS__))
#define InstrumentationPause(...)  FENCE_WRAPPER_VOID( _InstrumentationPause(__VA_ARGS__))
#define InstrumentationResume(...) FENCE_WRAPPER_VOID( _InstrumentationResume(__VA_ARGS__))
#define RegisterThread(...)        FENCE_WRAPPER(int,  _RegisterThread(__VA_ARGS__))
#define Testing(...)               FENCE_WRAPPER(bool, _Testing(__VA_ARGS__))
#define RunStart(...)              FENCE_WRAPPER_VOID( _RunStart(__VA_ARGS__))
#define RunEnd(...)                FENCE_WRAPPER_VOID( _RunEnd(__VA_ARGS__))
#define AssertAlways(...)          FENCE_WRAPPER_VOID( _AssertAlways(__VA_ARGS__))
#define AssertAtleastOnce(...)     FENCE_WRAPPER_VOID( _AssertAtleastOnce(__VA_ARGS__))
#define ContiguousMemoryHint(...)  FENCE_WRAPPER_VOID( _ContiguousMemoryHint(__VA_ARGS__))
// clang-format on

ASM_STUB(_Tracing);
ASM_STUB(_Instrumenting);
ASM_STUB(_InstrumentationPause);
ASM_STUB(_InstrumentationResume);
ASM_STUB(_RegisterThread);
ASM_STUB(_Testing);
ASM_STUB(_RunStart);
ASM_STUB(_RunEnd);
ASM_STUB(_AssertAlways);
ASM_STUB(_AssertAtleastOnce);
ASM_STUB(_ContiguousMemoryHint);

}
