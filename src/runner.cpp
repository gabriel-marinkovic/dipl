#include <getopt.h>
#include <stdio.h>
#include <string.h>

#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drsyms.h"
#include "drutil.h"
#include "drwrap.h"
#include "drx.h"

#include "common.h"

using namespace app;

void PrintBinary(uint64_t n, uint64_t total_length) {
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

uint64_t calculate_choose(uint64_t n, uint64_t k) {
  DR_ASSERT(n <= 64);
  uint64_t solutions[64] = {};
  solutions[0] = n - k + 1;
  for (uint64_t i = 1; i < k; ++i) {
    solutions[i] = solutions[i - 1] * (n - k + 1 + i) / (i + 1);
  }
  return solutions[k - 1];
}

// http://graphics.stanford.edu/~seander/bithacks.html
static inline uint64_t first_perm(uint64_t n, uint64_t c) { return (1 << c) - 1; }
static inline uint64_t last_perm(uint64_t n, uint64_t c) { return (1 << n) - (1 << (n - c)); }
static inline uint64_t next_perm(uint64_t v) {
  uint64_t t = (v | (v - 1)) + 1;
  uint64_t w = t | ((((t & -t) / (v & -v)) >> 1) - 1);
  return w;
}
static inline uint64_t perm_as_delta(uint64_t v) { return v ^ (v << 1); }

struct ThreadData {
  bool initialized_instrumentation;
  int volatile running;

  // Futex state.
  uint32_t* sleeping_on;
  uint32_t sleeping_until;

  thread_id_t thread_id;
  int64_t thread_idx;
  void* event;
  uint8_t* seg_base;
};

static void* the_mutex;
static client_id_t the_client_id;

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

/* Allocated TLS slot offsets */
enum TlsOffset {
  TLS_OFFSET_BUF_PTR,
  TLS_OFFSET_IS_INSTRUMENTING,
  TLS_OFFSET__COUNT,
};
static reg_id_t tls_seg;
static uint32_t tls_offs;
static int the_tls_idx;
#define TLS_SLOT(tls_base, enum_val) (void**)((uint8_t*)(tls_base) + tls_offs + (enum_val) * sizeof(void*))
#define BUF_PTR(tls_base) *(MemoryReference**)TLS_SLOT(tls_base, TLS_OFFSET_BUF_PTR)
#define IS_INSTRUMENTING(tls_base) *(uintptr_t*)TLS_SLOT(tls_base, TLS_OFFSET_IS_INSTRUMENTING)

static void insert_load_is_instrumenting(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t reg_ptr) {
  dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + TLS_OFFSET_IS_INSTRUMENTING * sizeof(void*),
                         reg_ptr);
}

static void insert_set_is_instrumenting(void* drcontext, instrlist_t* ilist, instr_t* where, uintptr_t value,
                                        reg_id_t scratch) {
  instrlist_insert_mov_immed_ptrsz(drcontext, value, opnd_create_reg(scratch), ilist, where, NULL, NULL);
  dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + TLS_OFFSET_IS_INSTRUMENTING * sizeof(void*),
                          scratch);
}

static uint64_t the_successful_run_count;
static uint64_t the_total_run_count;

// TODO: This currently assumes that we will have exactly 2 threads (not more OR less).
static int volatile the_next_thread_idx;
static ThreadData* the_threads[2];

static int volatile the_done;
static int volatile the_threads_waiting;
static int volatile the_threads_running;
static int volatile the_threads_successful;
static int volatile the_threads_successful_atleast_once = 1;

static uint64_t the_first_perm;
static uint64_t the_last_perm;
static uint64_t the_current_perm;
static uint64_t the_switch_mask;

static uint64_t volatile the_current_perm_log;
static uint64_t volatile the_switch_mask_log;
static uint64_t the_total_perm_count_log;
static uint64_t the_start_time_ms;
static uint64_t volatile the_last_run_completed_time_ms;

static const char* the_exit_path;

static void BestEffortAbort() {
  if (the_exit_path) {
    file_t df = dr_open_file(the_exit_path, DR_FILE_WRITE_REQUIRE_NEW);
    DR_ASSERT(df != INVALID_FILE);
    dr_close_file(df);
  }
  dr_abort();
}

static inline uint64_t atomic_load_u64(uint64_t volatile* x) {
  int64_t volatile * ptr = reinterpret_cast<int64_t volatile*>(x);
  int64_t val = dr_atomic_load64(ptr);
  return static_cast<uint64_t>(val);
}
static inline void atomic_store_u64(uint64_t volatile* x, uint64_t val) {
  int64_t volatile * ptr = reinterpret_cast<int64_t volatile*>(x);
  dr_atomic_store64(ptr, static_cast<int64_t>(val));
}

static void WrapInstrumentingWaitForAll() {}

static bool WrapNextRun() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  // Initialize the event on the first run.
  // We can't do this in `event_thread_init` because we don't know if a thread is a test thread or for example the main
  // application thread.
  if (!data->initialized_instrumentation) {
    data->event = dr_event_create();
    DR_ASSERT(data->event);
    data->thread_idx = dr_atomic_add32_return_sum(&the_next_thread_idx, 1) - 1;
    DR_ASSERT(data->thread_idx < ArrayCount(the_threads));
    the_threads[data->thread_idx] = data;
    data->initialized_instrumentation = true;
  }

  // dr_printf("Hello from WrapNextRun! TID: %d\n", data->thread_idx);

  if (dr_atomic_add32_return_sum(&the_threads_waiting, 1) < ArrayCount(the_threads)) {
    dr_event_wait(data->event);
    dr_event_reset(data->event);
  } else {
    if (data->thread_idx != 0) {
      dr_event_signal(the_threads[0]->event);
      dr_event_wait(data->event);
      dr_event_reset(data->event);
    }
  }

  if (data->thread_idx == 0) {
    dr_atomic_store32(&the_threads_waiting, 0);
    for (ThreadData* td : the_threads) {
      DR_ASSERT(!dr_atomic_load32(&td->running));
      dr_atomic_store32(&td->running, 1);
    }
    DR_ASSERT(data->event);
    dr_atomic_store32(&the_threads_running, ArrayCount(the_threads));

    if (the_current_perm <= the_last_perm) {
      the_switch_mask = perm_as_delta(the_current_perm);
      atomic_store_u64(&the_current_perm_log, the_current_perm);
      atomic_store_u64(&the_switch_mask_log, the_switch_mask);
      the_current_perm = next_perm(the_current_perm);

      // dr_printf("Using mask 0b");
      // PrintBinary(the_switch_mask_log, the_instrumented_instrs.count * 2);
      // dr_printf(" (0b");
      // PrintBinary(the_current_perm_log, the_instrumented_instrs.count * 2);
      // dr_printf(")\n");
    } else {
      dr_atomic_store32(&the_done, 1);

      for (ThreadData* other : the_threads) {
        if (other == data) continue;
        DR_ASSERT(other);
        DR_ASSERT(dr_atomic_load32(&other->running));
        dr_event_signal(other->event);
      }

      if (!dr_atomic_load32(&the_threads_successful_atleast_once)) {
        dr_printf("`MustAtleastOnce` was never true!\n");
        BestEffortAbort();
      }
    }
  }

  bool done = dr_atomic_load32(&the_done) != 0;
  if (done) {
    // Cleanup this thread's resources.
    dr_event_destroy(data->event);
    data->event = NULL;
  }

  drwrap_replace_native_fini(drcontext);
  return !done;
}

static void WrapRunDone() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  // dr_printf("Hello from WrapRunDone! %d TID: %d\n", result, data->thread_idx);

  int remaining = dr_atomic_add32_return_sum(&the_threads_running, -1);
  dr_atomic_store32(&data->running, 0);
  // dr_printf("REMAINING: %d\n", remaining);
  DR_ASSERT(remaining >= 0);

  if (remaining > 0) {
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

    // We will wait for the next test run in `WrapNextRun`.
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

    if (the_total_run_count % (the_total_perm_count_log / 128) == 0) {
      float percent = (float)the_total_run_count / (float)the_total_perm_count_log;
      float percent100 = 100.0f * percent;

      uint64_t t = dr_get_milliseconds();
      atomic_store_u64(&the_last_run_completed_time_ms, t);
      uint64_t elapsed_ms = t - the_start_time_ms;
      uint64_t estimated_total_ms = (uint64_t)((float)elapsed_ms / percent);

      uint64_t total_seconds = (estimated_total_ms - elapsed_ms) / 1000;
      uint64_t d = total_seconds / (3600 * 24);
      total_seconds %= (3600 * 24);
      uint64_t h = total_seconds / 3600;
      total_seconds %= 3600;
      uint64_t m = total_seconds / 60;
      uint64_t s = total_seconds % 60;

      dr_printf("Completed %.1f%% of all runs. Estimated time remaining: %llu days and %02llu:%02llu:%02llu\n",
                percent100, d, h, m, s);
    }
  }

  drwrap_replace_native_fini(drcontext);
}

static int WrapThreadIdx() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  drwrap_replace_native_fini(drcontext);
  return data->thread_idx;
}

static void WrapMustAlways(bool result) {
  void* drcontext = dr_get_current_drcontext();
  if (result) {
    dr_atomic_add32_return_sum(&the_threads_successful, 1);
  }
  drwrap_replace_native_fini(drcontext);
}

static void WrapMustAtleastOnce(bool result) {
  void* drcontext = dr_get_current_drcontext();
  dr_atomic_store32(&the_threads_successful_atleast_once, result ? 1 : 0);
  drwrap_replace_native_fini(drcontext);
}

static bool WakeNextThread(ThreadData* thread, bool go_to_sleep) {
  ThreadData* first_running_and_sleeping_idx = NULL;
  for (size_t i = 1; i < ArrayCount(the_threads); ++i) {
    int64_t next_thread_idx = (thread->thread_idx + i) % ArrayCount(the_threads);
    ThreadData* other = the_threads[next_thread_idx];
    DR_ASSERT(other);
    DR_ASSERT(other != thread);
    if (!dr_atomic_load32(&other->running)) continue;

    if (!first_running_and_sleeping_idx && !other->sleeping_on) {
      first_running_and_sleeping_idx = other;
    }

    if (go_to_sleep) {
      // dr_printf("sleeping in context switch point: %d (%d)\n", thread->thread_idx, thread->thread_id);
    }
    DR_ASSERT(thread->event);
    dr_event_signal(other->event);
    if (go_to_sleep) {
      dr_event_wait(thread->event);
      dr_event_reset(thread->event);
      // dr_printf("WAKING in context switch point: %d\n", thread->thread_idx);
    }
    return true;
  }

  if (first_running_and_sleeping_idx) {
    // dr_printf("FAILED TO WAKE, but there was a running thread which was sleeping: %d. Deadlock?\n",
    //           first_running_and_sleeping_idx->thread_idx);
  }
  return false;
}

static void ContextSwitchPoint(uintptr_t instr_addr_relative) {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  if (data->thread_idx < 0) return;
  int running = dr_atomic_load32(&the_threads_running);
  if (running == 0) return;

  bool should_switch = the_switch_mask & 1;
  the_switch_mask >>= 1;

  // dr_printf("%p In context switch point: %d\n", instr_addr_relative, data->thread_idx);

  for (InstrumentedInstruction& instr : the_instrumented_instrs) {
    if (instr.adddr_relative != instr_addr_relative) continue;
    if (!instr.is_syscall) continue;
    // dr_printf("    Context switch point is syscall, and we ate %d\n", should_switch);
    break;
  }

  if (should_switch) {
    bool woke_someone = WakeNextThread(data, true);
    // DR_ASSERT(woke_someone);
  }

  // dr_printf("LEAVING context switch point: %d\n", data->thread_idx);
}

static bool event_pre_syscall(void* drcontext, int sysnum) {
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  if (data->thread_idx < 0) return true;
  int running = dr_atomic_load32(&the_threads_running);
  if (running == 0) return true;

  // dr_printf("Hello from pre syscall event: 0x%x, TID: %d\n", sysnum, data->thread_idx);

  if (sysnum == 0xca /* futex */) {
    uint32_t* address = (uint32_t*)dr_syscall_get_param(drcontext, 0);
    int futex_op = (int)dr_syscall_get_param(drcontext, 1);

    if (futex_op == 0 /* FUTEX_WAIT */) {
      uint32_t expected_value = (uint32_t)dr_syscall_get_param(drcontext, 2);
      dr_printf("(TID: %d) PRE syscall; op: WAIT, address: %p, expected_value: %u\n", data->thread_idx, address,
                expected_value);

      DR_ASSERT(!data->sleeping_on);
      data->sleeping_on = address;
      data->sleeping_until = expected_value;

      bool awoke_someone = WakeNextThread(data, false);
      DR_ASSERT(awoke_someone);
    } else if (futex_op == 1 /* FUTEX_WAKE */) {
      dr_printf("(TID: %d) PRE syscall; op: WAKE, address: %p\n", data->thread_idx, address);
    }
  }

  return true;
}

static void event_post_syscall(void* drcontext, int sysnum) {
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  int running = dr_atomic_load32(&the_threads_running);
  if (data->thread_idx < 0) return;
  if (running == 0) return;

  // dr_printf("Hello from post syscall event: 0x%x, TID: %d, running: %d\n", sysnum, data->thread_idx, running);

  // if (sysnum == 0xca /* futex */) {
  //   DR_ASSERT(data->sleeping);
  //   data->sleeping = false;
  // }
}

static void instrument_instr(void* drcontext, instrlist_t* ilist, instr_t* where, instr_t* instr) {
  /* We need two scratch registers */
  reg_id_t reg_ptr, reg_tmp;
  /* we don't want to predicate this, because an instruction fetch always occurs */
  instrlist_set_auto_predicate(ilist, DR_PRED_NONE);
  if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
      drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) != DRREG_SUCCESS ||
      drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
    DR_ASSERT(false);
    return;
  }

  // TODO FILL

  /* Restore scratch registers */
  if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
      drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS ||
      drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
    DR_ASSERT(false);
  instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
}

static dr_emit_flags_t event_app_instruction(void* drcontext, void* tag, instrlist_t* bb, instr_t* where,
                                             bool for_trace, bool translating, void* user_data) {
  instr_t* instr_fetch = drmgr_orig_app_instr_for_fetch(drcontext);
  if (!instr_fetch) return DR_EMIT_DEFAULT;

  uintptr_t instr_addr = reinterpret_cast<uintptr_t>(instr_get_app_pc(instr_fetch));
  for (InstrumentedInstruction& instr : the_instrumented_instrs) {
    if (!instr.addr_absolute) continue;
    if (instr.addr_absolute != instr_addr) continue;

    dr_insert_clean_call(drcontext, bb, where, (void*)ContextSwitchPoint, false, 1,
                         OPND_CREATE_INTPTR(instr.adddr_relative));
    break;
  }

  // NOTE: See XXX i#1698: there are constraints for code between ldrex/strex pair...
  // dr_insert_clean_call(drcontext, bb, where, (void*)ContextSwitchPoint, false, 0);

  return DR_EMIT_DEFAULT;
}

/* We transform string loops into regular loops so we can more easily
 * monitor every memory reference they make.
 */
static dr_emit_flags_t event_bb_app2app(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating) {
  if (!drutil_expand_rep_string(drcontext, bb)) {
    DR_ASSERT(false);
    /* in release build, carry on: we'll just miss per-iter refs */
  }
  if (!drx_expand_scatter_gather(drcontext, bb, NULL)) {
    DR_ASSERT(false);
  }
  return DR_EMIT_DEFAULT;
}

static void event_thread_init(void* drcontext) {
  ThreadData* data = (ThreadData*)dr_thread_alloc(drcontext, sizeof(ThreadData));
  DR_ASSERT(data != NULL);
  memset(data, 0, sizeof(*data));
  drmgr_set_tls_field(drcontext, the_tls_idx, data);

  data->thread_idx = -1;
  data->thread_id = dr_get_thread_id(drcontext);
  data->seg_base = (uint8_t*)dr_get_dr_segment_base(tls_seg);
  DR_ASSERT(data->seg_base);
  IS_INSTRUMENTING(data->seg_base) = 0;
}

static void event_module_load(void* drcontext, const module_data_t* info, bool loaded) {
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

static bool event_filter_syscall(void* drcontext, int sysnum) { return true; }

static void event_thread_exit(void* drcontext) {
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  dr_thread_free(drcontext, data, sizeof(ThreadData));
}

static void event_exit(void) {
  dr_printf("\n\nTOTAL SUCCESSES: %llu / %llu\n", the_successful_run_count, the_total_run_count);

  for (auto& instr : the_instrumented_instrs) {
    DrThreadFreeArray(NULL, &instr.path);
  }
  DrThreadFreeArray(NULL, &the_instrumented_instrs);

  dr_log(NULL, DR_LOG_ALL, 1, "Client 'runner' exit\n");
  if (!dr_raw_tls_cfree(tls_offs, TLS_OFFSET__COUNT)) DR_ASSERT(false);

  if (!drmgr_unregister_tls_field(the_tls_idx) || !drmgr_unregister_thread_init_event(event_thread_init) ||
      !drmgr_unregister_thread_exit_event(event_thread_exit) || !drmgr_unregister_bb_app2app_event(event_bb_app2app) ||
      !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
      !drmgr_unregister_module_load_event(event_module_load) ||
      !drmgr_unregister_pre_syscall_event(event_pre_syscall) ||
      !drmgr_unregister_post_syscall_event(event_post_syscall) || drreg_exit() != DRREG_SUCCESS)
    DR_ASSERT(false);
  dr_unregister_filter_syscall_event(event_filter_syscall);

  dr_mutex_destroy(the_mutex);
  drutil_exit();
  drmgr_exit();
  drwrap_exit();
  drx_exit();
  drsym_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
  drreg_options_t ops = {sizeof(ops), 3, false};
  dr_set_client_name("Runner", "");

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
      {0, 0, 0, 0}
  };
  // clang-format on
  while ((opt = getopt_long(argc, (char**)argv, "i:p:", long_options, NULL)) != -1) {
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
      case '?':
        fprintf(stderr, "Usage: %s [--instructions_file=<file>] [--permutation=<hex>]\n", argv[0]);
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
      thread0_access_count += factor * instr.access_count1;
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
      PrintBinary(perm_as_delta(permutation), the_instrumented_instrs.count * 2);
      dr_printf(" (0b");
      PrintBinary(permutation, the_instrumented_instrs.count * 2);
      dr_printf(") (hex permutation: 0x%x)\n", permutation);
    }
    if (got_permutation) {
      the_first_perm = permutation;
      the_last_perm = permutation;
    } else {
      the_first_perm = first_perm(total_access_count, thread0_access_count);
      the_last_perm = last_perm(total_access_count, thread0_access_count);
      the_total_perm_count_log = calculate_choose(total_access_count, thread0_access_count);
    }
    the_current_perm = the_first_perm;
    the_current_perm_log = the_first_perm;
  }

  dr_register_exit_event(event_exit);
  dr_register_filter_syscall_event(event_filter_syscall);
  if (!drmgr_register_thread_init_event(event_thread_init) || !drmgr_register_thread_exit_event(event_thread_exit) ||
      !drmgr_register_bb_app2app_event(event_bb_app2app, NULL) ||
      !drmgr_register_bb_instrumentation_event(NULL /*analysis_func*/, event_app_instruction, NULL) ||
      !drmgr_register_module_load_event(event_module_load) || !drmgr_register_pre_syscall_event(event_pre_syscall) ||
      !drmgr_register_post_syscall_event(event_post_syscall))
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
  replace_native("InstrumentingWaitForAll", WrapInstrumentingWaitForAll);
  replace_native("NextRun", WrapNextRun);
  replace_native("RunDone", WrapRunDone);
  replace_native("ThreadIdx", WrapThreadIdx);
  replace_native("MustAlways", WrapMustAlways);
  replace_native("MustAtleastOnce", WrapMustAtleastOnce);

  dr_free_module_data(main_module);

  the_tls_idx = drmgr_register_tls_field();
  DR_ASSERT(the_tls_idx != -1);
  /* The TLS field provided by DR cannot be directly accessed from the code cache.
   * For better performance, we allocate raw TLS so that we can directly
   * access and update it with a single instruction.
   */
  if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, TLS_OFFSET__COUNT, alignof(void*))) DR_ASSERT(false);

  dr_log(NULL, DR_LOG_ALL, 1, "Client 'runner' initializing\n");

  // Deadlock detecting thread.
  the_start_time_ms = dr_get_milliseconds();
  atomic_store_u64(&the_last_run_completed_time_ms, the_start_time_ms);

  bool ok = dr_create_client_thread(
      [](void*) {
        while (true) {
          uint64_t before = atomic_load_u64(&the_last_run_completed_time_ms);
          dr_sleep(60 * 1000);
          uint64_t after = atomic_load_u64(&the_last_run_completed_time_ms);
          if (after <= before) {
            uint64_t perm = atomic_load_u64(&the_current_perm_log);
            dr_printf("!!! DEADLOCK DETECTED !!! For permutation: 0x%llx\n", perm);
            BestEffortAbort();
          }
        }
      },
      NULL);
}
