#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drsyms.h"
#include "drutil.h"
#include "drwrap.h"
#include "drx.h"

#include "common.h"

using namespace app;

// DynamoRIO-like wrappers for unsinged integer atomic operations.
static inline uint64_t dr_atomic_load_u64(uint64_t volatile* x) {
  int64_t volatile* ptr = reinterpret_cast<int64_t volatile*>(x);
  int64_t val = dr_atomic_load64(ptr);
  return static_cast<uint64_t>(val);
}
static inline void dr_atomic_store_u64(uint64_t volatile* x, uint64_t val) {
  int64_t volatile* ptr = reinterpret_cast<int64_t volatile*>(x);
  dr_atomic_store64(ptr, static_cast<int64_t>(val));
}

// General utilities.
static uint64_t GetElapsedMillisCoarse() {
  // RECONSIDER: Safe to call libc?
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
  return (static_cast<uint64_t>(ts.tv_sec) * 1000000000ULL + static_cast<uint64_t>(ts.tv_nsec)) / 1000000ULL;
}

static void PrintBinary(uint64_t n, uint64_t total_length) {
  int num_bits = 0;
  uint64_t temp = n;
  while (temp > 0) {
    num_bits++;
    temp >>= 1;
  }
  int leading_zeros = total_length - num_bits;
  if (leading_zeros < 0) leading_zeros = 0;
  for (int i = 0; i < leading_zeros; i++) {
    dr_printf("0");
  }
  if (n == 0 && total_length > 0) {
    dr_printf("0");
  } else {
    for (int i = num_bits - 1; i >= 0; i--) {
      dr_printf("%d", (n >> i) & 1);
    }
  }
}

// Permutation utilities.
static uint64_t CalculateChoose(uint64_t n, uint64_t k) {
  DR_ASSERT(n <= 64);
  uint64_t solutions[64] = {};
  solutions[0] = n - k + 1;
  for (uint64_t i = 1; i < k; ++i) {
    solutions[i] = solutions[i - 1] * (n - k + 1 + i) / (i + 1);
  }
  return solutions[k - 1];
}

// http://graphics.stanford.edu/~seander/bithacks.html
static inline uint64_t FirstPermutation(uint64_t n, uint64_t c) { return (1 << c) - 1; }
static inline uint64_t LastPermutation(uint64_t n, uint64_t c) { return (1 << n) - (1 << (n - c)); }
static inline uint64_t NextPermutation(uint64_t v) {
  uint64_t t = (v | (v - 1)) + 1;
  uint64_t w = t | ((((t & -t) / (v & -v)) >> 1) - 1);
  return w;
}
static inline uint64_t DeltaFromPermutation(uint64_t v) { return v ^ (v << 1); }

// Global state.
static bool the_trace;
#define TRACE(code)  \
  do {               \
    if (the_trace) { \
      code;          \
    };               \
  } while (0)

static void* the_mutex;
static client_id_t the_client_id;
static int the_tls_idx;

struct InstrumentedInstruction {
  String path;
  uintptr_t adddr_relative;
  uintptr_t module_base;
  uintptr_t addr_absolute;
  bool is_syscall;
  uint64_t access_count1;
  uint64_t access_count2;
};
static Array<InstrumentedInstruction> the_instrumented_instrs;

struct ThreadData {
  bool initialized_instrumentation;
  int volatile running;
  thread_id_t thread_id;
  int64_t thread_idx;
  void* event;
};

static ThreadData* the_threads[2];

static int volatile the_done;
static int volatile the_threads_waiting;
static int volatile the_threads_running;
static int volatile the_threads_successful;
static int volatile the_threads_successful_atleast_once[64];
static int volatile the_threads_successful_atleast_once_used[64];

static uint64_t the_successful_run_count;
static uint64_t the_total_run_count;
static uint64_t the_first_perm;
static uint64_t the_last_perm;
static uint64_t the_current_perm;
static uint64_t the_switch_mask;

static uint64_t volatile the_current_perm_log;
static uint64_t volatile the_switch_mask_log;
static uint64_t the_total_perm_count_log;
static uint64_t the_start_time_ms;
static uint64_t volatile the_last_run_completed_time_ms;

// NOTE: `dr_abort` is very flaky on Linux because threads created by `dr_create_client_thread` get their own PID.
// All threads should call `BestEffortAbort` instead of plain `dr_abort`.
// All threads created by `dr_create_client_thread` should periodically (as often as possible) check
// `the_all_threads_should_abort` and call `dr_abort` if set.
// `BestEffortAbort` also creates an `exit` file which the outer process can use to terminate us in case of a deadlock.
static const char* the_exit_path;
static int volatile the_all_threads_should_abort;
static void BestEffortAbort() {
  dr_atomic_store32(&the_all_threads_should_abort, 1);
  if (the_exit_path) {
    file_t df = dr_open_file(the_exit_path, DR_FILE_WRITE_APPEND);
    DR_ASSERT(df != INVALID_FILE);
    dr_close_file(df);
  }
  dr_abort();
  while (1) {
    volatile int x = 0;
    volatile int y = x / x;
  }
}

// `Wrap*` functions.

static int WrapRegisterThread(int preferred_thread_idx = -1) {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  DR_ASSERT(preferred_thread_idx <= 1);
  DR_ASSERT(!data->initialized_instrumentation);

  dr_mutex_lock(the_mutex);
  if (preferred_thread_idx < 0) {
    for (int i = 0; i < ArrayCount(the_threads); ++i) {
      if (!the_threads[i]) {
        preferred_thread_idx = i;
        break;
      }
    }
    DR_ASSERT(preferred_thread_idx >= 0 && preferred_thread_idx < ArrayCount(the_threads));
  }
  DR_ASSERT(!the_threads[preferred_thread_idx]);
  data->thread_idx = preferred_thread_idx;
  the_threads[data->thread_idx] = data;
  dr_mutex_unlock(the_mutex);

  data->event = dr_event_create();
  DR_ASSERT(data->event);
  data->initialized_instrumentation = true;

  drwrap_replace_native_fini(drcontext);
  return data->thread_idx;
}

static bool WrapTesting() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  bool done = dr_atomic_load32(&the_done) != 0;
  if (done) {
    if (data->thread_idx == 0) {
      // We are done, unblock all other threads and check `AssertAtleastOnce` instances.
      for (ThreadData* other : the_threads) {
        if (other == data) continue;
        dr_event_signal(data->event);
      }

      for (int i = 0; i < ArrayCount(the_threads_successful_atleast_once); ++i) {
        if (dr_atomic_load32(&the_threads_successful_atleast_once_used[i]) &&
            !dr_atomic_load32(&the_threads_successful_atleast_once[i])) {
          dr_printf("`AssertAtleastOnce` condition with idx: %d was never true!\n", i);
        }
      }
    }

    // Cleanup this thread's resources.
    dr_event_destroy(data->event);
    data->event = NULL;
  } else {
    if (dr_atomic_add32_return_sum(&the_threads_waiting, 1) < ArrayCount(the_threads)) {
      TRACE(printf("Sleeping in WrapTesting: %ld\n", data->thread_idx));
      dr_event_wait(data->event);
      dr_event_reset(data->event);
    } else {
      dr_atomic_store32(&the_threads_waiting, 0);

      if (data->thread_idx != 0) {
        dr_event_signal(the_threads[0]->event);
        dr_event_wait(data->event);
        dr_event_reset(data->event);
      }
    }
  }

  TRACE(printf("Leaving WrapTesting: %ld\n", data->thread_idx));
  drwrap_replace_native_fini(drcontext);

  return !done;
}

static void WrapRunStart() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  DR_ASSERT(data->initialized_instrumentation);

  TRACE(printf("Hello from WrapRunStart! TID: %ld\n", data->thread_idx));

  int threads_waiting = dr_atomic_add32_return_sum(&the_threads_waiting, 1);
  if (threads_waiting < ArrayCount(the_threads)) {
    DR_ASSERT(threads_waiting > 1 || data->thread_idx == 0);

    int64_t next_idx = (data->thread_idx + 1) % ArrayCount(the_threads);
    ThreadData* next = the_threads[next_idx];
    dr_event_signal(next->event);

    dr_event_wait(data->event);
    dr_event_reset(data->event);
  } else {
    DR_ASSERT(data->thread_idx != 0);
    dr_event_signal(the_threads[0]->event);
    dr_event_wait(data->event);
    dr_event_reset(data->event);
  }

  if (data->thread_idx == 0) {
    dr_atomic_store32(&the_threads_waiting, 0);
    for (ThreadData* td : the_threads) {
      DR_ASSERT(!dr_atomic_load32(&td->running));
      dr_atomic_store32(&td->running, 1);
    }
    DR_ASSERT(data->event);
    dr_atomic_store32(&the_threads_running, ArrayCount(the_threads));

    the_switch_mask = DeltaFromPermutation(the_current_perm);
    dr_atomic_store_u64(&the_current_perm_log, the_current_perm);
    dr_atomic_store_u64(&the_switch_mask_log, the_switch_mask);
    the_current_perm = NextPermutation(the_current_perm);

    // dr_printf("Using mask 0b");
    // PrintBinary(the_switch_mask_log, the_instrumented_instrs.count * 2);
    // dr_printf(" (0b");
    // PrintBinary(the_current_perm_log, the_instrumented_instrs.count * 2);
    // dr_printf(")\n");

    if (the_current_perm >= the_last_perm) {
      dr_atomic_store32(&the_done, 1);
    }
  }

  TRACE(printf("Leaving WrapRunStart TID: %ld\n", data->thread_idx));

  // TODO: Thread 0 will always start from WrapRunStart.
  drwrap_replace_native_fini(drcontext);
}

static inline uint64_t min(uint64_t a, uint64_t b) { return a < b ? a : b; }

static void WrapRunEnd() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  // dr_printf("Hello from WrapRunEnd! %d TID: %d\n", result, data->thread_idx);

  int remaining = dr_atomic_add32_return_sum(&the_threads_running, -1);
  dr_atomic_store32(&data->running, 0);
  // dr_printf("REMAINING: %d\n", remaining);
  DR_ASSERT(remaining >= 0);

  if (remaining > 0) {
    TRACE(dr_printf("We are done, waiting for others: %d\n", data->thread_idx));
    // There are still other threads running, so wake someone else.
    bool woke_someone = false;
    for (size_t i = 1; i < ArrayCount(the_threads); ++i) {
      uint64_t next_thread_idx = (data->thread_idx + i) % ArrayCount(the_threads);
      ThreadData* other = the_threads[next_thread_idx];
      DR_ASSERT(other);
      DR_ASSERT(other != data);
      if (dr_atomic_load32(&other->running)) {
        dr_event_signal(other->event);
        woke_someone = true;
        break;
      }
    }
    DR_ASSERT(woke_someone);

    // We will wait for the next test run in `WrapTesting`.
  } else {
    int successes = dr_atomic_load32(&the_threads_successful);
    dr_atomic_store32(&the_threads_successful, 0);
    bool all_successful = (successes == ArrayCount(the_threads));
    if (all_successful) ++the_successful_run_count;
    ++the_total_run_count;

    if (!all_successful) {
      const char* prefix = all_successful ? ":) :)" : "!!!!!";
      dr_printf("%s %d / %d threads FAILED for mask 0b", prefix, (ArrayCount(the_threads) - successes),
                ArrayCount(the_threads));
      PrintBinary(the_switch_mask_log, the_instrumented_instrs.count * 2);
      dr_printf(" (0b");
      PrintBinary(the_current_perm_log, the_instrumented_instrs.count * 2);
      dr_printf(") (hex permutation: 0x%x)\n", the_current_perm_log);

      BestEffortAbort();
    }

    uint64_t t = GetElapsedMillisCoarse();
    dr_atomic_store_u64(&the_last_run_completed_time_ms, t);

    const uint64_t runs_before_logging = min(100000, (the_total_perm_count_log / min(the_total_perm_count_log, 128)));
    if (the_total_run_count % runs_before_logging == 0) {
      // TODO: Investigate why using floating point operations (in particular printing, with either `printf` or
      // `dr_printf`) crashes us with the `basic_passing` example.
      // https://dynamorio.org/transparency.html#sec_trans_floating_point
      uint64_t percent = (the_total_run_count * 100) / the_total_perm_count_log;

      uint64_t elapsed_ms = t - the_start_time_ms;
      uint64_t estimated_total_ms = elapsed_ms * the_total_perm_count_log / the_total_run_count;

      uint64_t total_seconds = (estimated_total_ms - elapsed_ms) / 1000;
      uint64_t d = total_seconds / (3600 * 24);
      total_seconds %= (3600 * 24);
      uint64_t h = total_seconds / 3600;
      total_seconds %= 3600;
      uint64_t m = total_seconds / 60;
      uint64_t s = total_seconds % 60;

      printf("Completed %lu%% of all runs. Estimated time remaining: %lu days and %02lu:%02lu:%02lu\n", percent, d, h,
             m, s);
    }
  }

  drwrap_replace_native_fini(drcontext);
}

static void WrapAssertAlways(bool result) {
  void* drcontext = dr_get_current_drcontext();
  if (result) {
    dr_atomic_add32_return_sum(&the_threads_successful, 1);
  }
  drwrap_replace_native_fini(drcontext);
}

static void WrapAssertAtleastOnce(int condition_idx, bool result) {
  void* drcontext = dr_get_current_drcontext();
  dr_atomic_store32(&the_threads_successful_atleast_once_used[condition_idx], 1);
  // if (result) dr_printf("WrapAssertAtleastOnce: %d %d\n", condition_idx, result);
  if (result) dr_atomic_store32(&the_threads_successful_atleast_once[condition_idx], 1);
  drwrap_replace_native_fini(drcontext);
}

static bool WakeNextThread(ThreadData* thread) {
  for (size_t i = 1; i < ArrayCount(the_threads); ++i) {
    int64_t next_thread_idx = (thread->thread_idx + i) % ArrayCount(the_threads);
    ThreadData* other = the_threads[next_thread_idx];
    DR_ASSERT(other);
    DR_ASSERT(other != thread);
    if (!dr_atomic_load32(&other->running)) continue;

    // dr_printf("sleeping in context switch point: %d (%d)\n", thread->thread_idx, thread->thread_id);
    DR_ASSERT(thread->event);
    dr_event_signal(other->event);
    dr_event_wait(thread->event);
    dr_event_reset(thread->event);
    // dr_printf("WAKING in context switch point: %d\n", thread->thread_idx);
    return true;
  }

  return false;
}

static void ContextSwitchPoint(uintptr_t instr_addr) {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  if (data->thread_idx < 0) return;
  int running = dr_atomic_load32(&the_threads_running);
  if (running == 0) return;

  bool should_switch = the_switch_mask & 1;
  the_switch_mask >>= 1;

  // dr_printf("%p In context switch point: %d\n", instr_addr, data->thread_idx);

  if (should_switch) {
    TRACE(dr_printf("%d going to sleep before executing 0x%x\n", data->thread_idx, instr_addr));
    bool woke_someone = WakeNextThread(data);
    // DR_ASSERT(woke_someone);
  }

  TRACE(dr_printf("%d will execute 0x%x\n", data->thread_idx, instr_addr));
}

static dr_emit_flags_t EventAppInstruction(void* drcontext, void* tag, instrlist_t* bb, instr_t* where, bool for_trace,
                                           bool translating, void* user_data) {
  instr_t* instr_fetch = drmgr_orig_app_instr_for_fetch(drcontext);
  if (!instr_fetch) return DR_EMIT_DEFAULT;

  uintptr_t instr_addr = reinterpret_cast<uintptr_t>(instr_get_app_pc(instr_fetch));
  for (InstrumentedInstruction& instr : the_instrumented_instrs) {
    if (!instr.addr_absolute) continue;
    if (instr.addr_absolute != instr_addr) continue;

    dr_insert_clean_call(drcontext, bb, where, (void*)ContextSwitchPoint, false, 1,
                         OPND_CREATE_INTPTR(instr.addr_absolute));
    break;
  }

  // NOTE: See XXX i#1698: there are constraints for code between ldrex/strex pair...
  // dr_insert_clean_call(drcontext, bb, where, (void*)ContextSwitchPoint, false, 0);

  return DR_EMIT_DEFAULT;
}

/* We transform string loops into regular loops so we can more easily
 * monitor every memory reference they make.
 */
static dr_emit_flags_t EventB2BApp2App(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating) {
  if (!drutil_expand_rep_string(drcontext, bb)) {
    DR_ASSERT(false);
    /* in release build, carry on: we'll just miss per-iter refs */
  }
  if (!drx_expand_scatter_gather(drcontext, bb, NULL)) {
    DR_ASSERT(false);
  }
  return DR_EMIT_DEFAULT;
}

static void EventThreadInit(void* drcontext) {
  ThreadData* data = (ThreadData*)dr_thread_alloc(drcontext, sizeof(ThreadData));
  DR_ASSERT(data != NULL);
  memset(data, 0, sizeof(*data));
  drmgr_set_tls_field(drcontext, the_tls_idx, data);

  data->thread_idx = -1;
  data->thread_id = dr_get_thread_id(drcontext);
}

static void EventModuleLoad(void* drcontext, const module_data_t* info, bool loaded) {
  dr_mutex_lock(the_mutex);
  Defer(dr_mutex_unlock(the_mutex));

  for (InstrumentedInstruction& instr : the_instrumented_instrs) {
    if (instr.path != Wrap(info->full_path)) continue;
    DR_ASSERT(instr.module_base == 0);
    instr.module_base = reinterpret_cast<uintptr_t>(info->start);
    instr.addr_absolute = instr.module_base + instr.adddr_relative;
    dr_printf("Initialized instr: %p -> %p (syscall: %d)\n", reinterpret_cast<void*>(instr.adddr_relative),
              reinterpret_cast<void*>(instr.addr_absolute), instr.is_syscall);
  }
}

static void EventThreadExit(void* drcontext) {
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  dr_thread_free(drcontext, data, sizeof(ThreadData));
}

static void EventExit(void) {
  dr_printf("\n\nTOTAL SUCCESSES: %llu / %llu\n", the_successful_run_count, the_total_run_count);

  for (auto& instr : the_instrumented_instrs) {
    DrThreadFreeArray(NULL, &instr.path);
  }
  DrThreadFreeArray(NULL, &the_instrumented_instrs);

  dr_log(NULL, DR_LOG_ALL, 1, "Client 'runner' exit\n");

  if (!drmgr_unregister_tls_field(the_tls_idx) || !drmgr_unregister_thread_init_event(EventThreadInit) ||
      !drmgr_unregister_thread_exit_event(EventThreadExit) || !drmgr_unregister_bb_app2app_event(EventB2BApp2App) ||
      !drmgr_unregister_bb_insertion_event(EventAppInstruction) ||
      !drmgr_unregister_module_load_event(EventModuleLoad) || drreg_exit() != DRREG_SUCCESS)
    DR_ASSERT(false);

  dr_mutex_destroy(the_mutex);
  drutil_exit();
  drmgr_exit();
  drwrap_exit();
  drx_exit();
  drsym_exit();

  dr_atomic_store32(&the_all_threads_should_abort, 1);
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
  drreg_options_t ops = {sizeof(ops), 3, false};
  dr_set_client_name("runner", "");

  if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drutil_init() || !drwrap_init() || !drx_init() ||
      drsym_init(0) != DRSYM_SUCCESS)
    DR_ASSERT(false);

  const char* instr_path = NULL;
  bool got_permutation = false;
  uint64_t permutation = 0;
  int opt;
  // clang-format off
  static struct option long_options[] = {
      {"instructions_file", required_argument, 0, 'i'},
      {"exit_file",         required_argument, 0, 'e'},
      {"permutation",       required_argument, 0, 'p'},
      {"trace",             optional_argument, 0, 't'},
      {0, 0, 0, 0}
  };
  // clang-format on
  while ((opt = getopt_long(argc, (char**)argv, "e:i:p:t", long_options, NULL)) != -1) {
    switch (opt) {
      case 'e':
        the_exit_path = optarg;
        break;
      case 'i':
        instr_path = optarg;
        break;
      case 'p':
        got_permutation = true;
        permutation = strtoull(optarg, NULL, 16);
        break;
      case 't':
        the_trace = true;
        break;
      case '?':
        fprintf(stderr, "Bad CLI options.\n");
        exit(EXIT_FAILURE);
      default:
        break;
    }
  }

  DR_ASSERT(instr_path);
  DR_ASSERT(the_exit_path);
  dr_printf("Instructions file: %s\n", instr_path);

  // Initialize `the_instrumented_instrs` from path given in `argv`.
  {
    file_t instr_file = dr_open_file(instr_path, DR_FILE_READ);
    DR_ASSERT(instr_file != INVALID_FILE);

    BufferedFileReader instr_reader;
    BufferedFileReader::Make(&instr_reader, NULL, instr_file, 1024);

    uint64_t instr_count = 0;
    bool ok = instr_reader.ReadUint64LE(&instr_count);
    DR_ASSERT(ok);
    if (instr_count == 0) {
      dr_fprintf(STDERR, "Error: no instructions provided in '%s'\n", instr_path);
      dr_abort();
    } else if (instr_count >= 32) {
      dr_fprintf(STDERR, "Error: too many instructions (%llu) provided in '%s'\n", instr_count, instr_path);
      dr_abort();
    }

    the_instrumented_instrs = DrThreadAllocArray<InstrumentedInstruction>(NULL, instr_count);
    for (uint64_t i = 0; i < instr_count; ++i) {
      ok = instr_reader.ReadString(NULL, &the_instrumented_instrs[i].path);
      DR_ASSERT(ok);
      ok = instr_reader.ReadUint64LE(&the_instrumented_instrs[i].adddr_relative);
      DR_ASSERT(ok);

      uint8_t is_syscall = 0;
      ok = instr_reader.ReadUint8LE(&is_syscall);
      DR_ASSERT(ok);
      the_instrumented_instrs[i].is_syscall = (is_syscall != 0);

      ok = instr_reader.ReadUint64LE(&the_instrumented_instrs[i].access_count1);
      DR_ASSERT(ok);
      ok = instr_reader.ReadUint64LE(&the_instrumented_instrs[i].access_count2);
      DR_ASSERT(ok);

      dr_printf("Parsed instr %.*s, %llu (access count: %llu, %llu)\n", StringArgs(the_instrumented_instrs[i].path),
                the_instrumented_instrs[i].adddr_relative, the_instrumented_instrs[i].access_count1,
                the_instrumented_instrs[i].access_count2);
    }

    instr_reader.Destroy();
  }

  // Initialize global permutation state.
  {
    uint64_t thread0_access_count = 0;
    uint64_t total_access_count = 0;
    for (InstrumentedInstruction& instr : the_instrumented_instrs) {
      int factor = (instr.is_syscall ? 2 : 1);
      // TODO: This is very incorrect if threads don't execute the same code.
      // CHANGE: try `access_count1` or `access_count2`.
      thread0_access_count += factor * instr.access_count2;
      total_access_count += factor * (instr.access_count1 + instr.access_count2);
    }

    if (total_access_count < 1 || total_access_count > 64) {
      dr_printf("Invalid instruction access count: %llu. Must be in range [1, 64].\n", total_access_count);
      dr_abort();
    }
    if (thread0_access_count == 0 || thread0_access_count == total_access_count < 1) {
      dr_printf("Invalid instruction access count for thread0: %llu (total count is %llu).\n", thread0_access_count,
                total_access_count);
      dr_abort();
    }

    if (got_permutation) {
      dr_printf("\nUsing explicit permutation: 0b", permutation);
      PrintBinary(DeltaFromPermutation(permutation), the_instrumented_instrs.count * 2);
      dr_printf(" (0b");
      PrintBinary(permutation, the_instrumented_instrs.count * 2);
      dr_printf(") (hex permutation: 0x%x)\n", permutation);
    }
    if (got_permutation) {
      the_first_perm = permutation;
      the_last_perm = permutation;
    } else {
      the_first_perm = FirstPermutation(total_access_count, thread0_access_count);
      the_last_perm = LastPermutation(total_access_count, thread0_access_count);
      the_total_perm_count_log = CalculateChoose(total_access_count, thread0_access_count);
    }
    the_current_perm = the_first_perm;
    the_current_perm_log = the_first_perm;
  }

  dr_register_exit_event(EventExit);
  if (!drmgr_register_thread_init_event(EventThreadInit) || !drmgr_register_thread_exit_event(EventThreadExit) ||
      !drmgr_register_bb_app2app_event(EventB2BApp2App, NULL) ||
      !drmgr_register_bb_instrumentation_event(NULL /*analysis_func*/, EventAppInstruction, NULL) ||
      !drmgr_register_module_load_event(EventModuleLoad))
    DR_ASSERT(false);

  the_client_id = id;
  the_mutex = dr_mutex_create();

  module_data_t* main_module = dr_get_main_module();
  DR_ASSERT(main_module);

  auto replace_native = [main_module](const char* name, auto* replace_with) {
    dr_printf("Replacing function %s\n", name);

    size_t offset = 0;
    drsym_error_t status = drsym_lookup_symbol(main_module->full_path, name, &offset, DRSYM_DEFAULT_FLAGS);
    DR_ASSERT(status == DRSYM_SUCCESS);

    uintptr_t addr = reinterpret_cast<uintptr_t>(main_module->start) + offset;
    bool ok =
        drwrap_replace_native(reinterpret_cast<app_pc>(addr),
                              reinterpret_cast<app_pc>(reinterpret_cast<void*>(replace_with)), true, 0, NULL, false);
  };

  // `Instrumenting` is already `return false`.
  // `InstrumentationPause` is already noop.
  // `InstrumentationResume` is already noop.
  replace_native("_RegisterThread", WrapRegisterThread);
  replace_native("_Testing", WrapTesting);
  replace_native("_RunStart", WrapRunStart);
  replace_native("_RunEnd", WrapRunEnd);
  replace_native("_AssertAlways", WrapAssertAlways);
  replace_native("_AssertAtleastOnce", WrapAssertAtleastOnce);

  dr_free_module_data(main_module);

  the_tls_idx = drmgr_register_tls_field();
  DR_ASSERT(the_tls_idx != -1);
  dr_log(NULL, DR_LOG_ALL, 1, "Client 'runner' initializing\n");

  // Deadlock detecting thread.
  the_start_time_ms = GetElapsedMillisCoarse();
  dr_atomic_store_u64(&the_last_run_completed_time_ms, the_start_time_ms);

  bool ok = dr_create_client_thread(
      [](void*) {
        while (true) {
          uint64_t before = dr_atomic_load_u64(&the_last_run_completed_time_ms);
          dr_sleep(1000);
          if (dr_atomic_load32(&the_all_threads_should_abort)) dr_abort();

          uint64_t after = GetElapsedMillisCoarse();
          if (after - before >= 60'000) {
            uint64_t perm = dr_atomic_load_u64(&the_current_perm_log);
            dr_printf("!!! DEADLOCK DETECTED !!! For permutation: 0x%llx\n", perm);
            BestEffortAbort();
          }
        }
      },
      NULL);
  DR_ASSERT(ok);
}
