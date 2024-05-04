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
  thread_id_t thread_id;
  uint64_t thread_idx;
  void* event;
  uint8_t* seg_base;
};

static void* the_mutex;
static client_id_t the_client_id;

struct InstrumentedInstruction {
  String path;
  uintptr_t profiled_instruction_relative;
  uintptr_t base;
  uintptr_t profiled_instruction_absolute;
};

static InstrumentedInstruction the_instrumented_instructions[] = {
    {Wrap("/home/gabriel/dipl/build/example/basic"), 0x1230, 0, 0},
    {Wrap("/home/gabriel/dipl/build/example/basic"), 0x1238, 0, 0},
    {Wrap("/home/gabriel/dipl/build/example/basic"), 0x123e, 0, 0},
    {Wrap("/home/gabriel/dipl/build/example/basic"), 0x1246, 0, 0},
    {Wrap("/home/gabriel/dipl/build/example/basic"), 0x124c, 0, 0},
};

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

static int total_runs;
static int total_successes;

// TODO: This currently assumes that we will have exactly 2 threads (not more OR less).
static int volatile the_next_thread_idx;
static ThreadData* the_threads[2];

static int volatile the_done;
static int volatile the_threads_waiting;
static int volatile the_threads_running;
static int volatile the_threads_successful;

static uint64_t the_first_perm =
    first_perm(ArrayCount(the_instrumented_instructions) * 2, ArrayCount(the_instrumented_instructions));
static uint64_t the_last_perm =
    last_perm(ArrayCount(the_instrumented_instructions) * 2, ArrayCount(the_instrumented_instructions));
static uint64_t the_current_perm = the_first_perm;
static uint64_t the_switch_mask = 0;
static uint64_t the_current_perm_log;
static uint64_t the_switch_mask_log;

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
    dr_atomic_store32(&the_threads_running, ArrayCount(the_threads));

    if (the_current_perm <= the_last_perm) {
      the_switch_mask = perm_as_delta(the_current_perm);
      the_current_perm_log = the_current_perm;
      the_switch_mask_log = the_switch_mask;
      the_current_perm = next_perm(the_current_perm);
    } else {
      dr_atomic_store32(&the_done, 1);

      for (ThreadData* other : the_threads) {
        if (other == data) continue;
        DR_ASSERT(other);
        DR_ASSERT(dr_atomic_load32(&other->running));
        dr_event_signal(other->event);
      }
    }
  }

  bool done = dr_atomic_load32(&the_done) != 0;
  if (done) {
    // Cleanup this thread's resources.
    dr_event_destroy(data->event);
  }

  drwrap_replace_native_fini(drcontext);
  return !done;
}

static void WrapReportTestResult(bool result) {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  // dr_printf("Hello from WrapReportTestResult! %d TID: %d\n", result, data->thread_idx);

  if (result) {
    dr_atomic_add32_return_sum(&the_threads_successful, 1);
  }

  int remaining = dr_atomic_add32_return_sum(&the_threads_running, -1);
  dr_atomic_store32(&data->running, 0);
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
    if (all_successful) ++total_successes;
    ++total_runs;

    const char* prefix = all_successful ? ":) :)": "!!!!!";
    dr_printf("%s %d / %d threads FAILED for mask 0b", prefix, (ArrayCount(the_threads) - successes),
              ArrayCount(the_threads));
    PrintBinary(the_switch_mask_log, ArrayCount(the_instrumented_instructions) * 2);
    dr_printf(" (0b");
    PrintBinary(the_current_perm_log, ArrayCount(the_instrumented_instructions) * 2);
    dr_printf(")\n");
  }

  drwrap_replace_native_fini(drcontext);
}

static void ContextSwitchPoint(uintptr_t instr_addr_relative) {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  bool should_switch = the_switch_mask & 1;
  the_switch_mask >>= 1;

  if (should_switch) {
    bool woke_someone = false;
    for (size_t i = 1; i < ArrayCount(the_threads); ++i) {
      uint64_t next_thread_idx = (data->thread_idx + i) % ArrayCount(the_threads);
      ThreadData* other = the_threads[next_thread_idx];
      DR_ASSERT(other);
      DR_ASSERT(other != data);
      if (dr_atomic_load32(&other->running)) {
        dr_event_signal(other->event);
        dr_event_wait(data->event);
        dr_event_reset(data->event);
        woke_someone = true;
        break;
      }
    }
    // RECONSIDER: Add this assert back when we do actual scheduling.
    // DR_ASSERT(woke_someone);
  }
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
  for (InstrumentedInstruction& instr : the_instrumented_instructions) {
    if (!instr.profiled_instruction_absolute) continue;
    if (instr.profiled_instruction_absolute != instr_addr) continue;

    // RECONSIDER: save fp state?
    dr_insert_clean_call(drcontext, bb, where, (void*)ContextSwitchPoint, true, 1,
                         OPND_CREATE_INTPTR(instr.profiled_instruction_relative));
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

  data->thread_id = dr_get_thread_id(drcontext);
  data->seg_base = (uint8_t*)dr_get_dr_segment_base(tls_seg);
  DR_ASSERT(data->seg_base);
  IS_INSTRUMENTING(data->seg_base) = 0;
}

static void event_module_load(void* drcontext, const module_data_t* info, bool loaded) {
  dr_mutex_lock(the_mutex);
  Defer(dr_mutex_unlock(the_mutex));

  for (InstrumentedInstruction& instr : the_instrumented_instructions) {
    if (instr.path != Wrap(info->full_path)) continue;
    DR_ASSERT(instr.base == 0);
    instr.base = reinterpret_cast<uintptr_t>(info->start);
    instr.profiled_instruction_absolute = instr.base + instr.profiled_instruction_relative;
    dr_printf("Initialized instr: %p -> %p\n", reinterpret_cast<void*>(instr.profiled_instruction_relative),
              reinterpret_cast<void*>(instr.profiled_instruction_absolute));
  }
}

static void event_thread_exit(void* drcontext) {
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  dr_thread_free(drcontext, data, sizeof(ThreadData));
}

static void event_exit(void) {
  dr_printf("\n\nTOTAL SUCCESSES: %d / %d\n", total_successes, total_runs);

  dr_log(NULL, DR_LOG_ALL, 1, "Client 'runner' exit\n");
  if (!dr_raw_tls_cfree(tls_offs, TLS_OFFSET__COUNT)) DR_ASSERT(false);

  if (!drmgr_unregister_tls_field(the_tls_idx) || !drmgr_unregister_thread_init_event(event_thread_init) ||
      !drmgr_unregister_thread_exit_event(event_thread_exit) || !drmgr_unregister_bb_app2app_event(event_bb_app2app) ||
      !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
      !drmgr_unregister_module_load_event(event_module_load) || drreg_exit() != DRREG_SUCCESS)
    DR_ASSERT(false);

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

  dr_register_exit_event(event_exit);
  if (!drmgr_register_thread_init_event(event_thread_init) || !drmgr_register_thread_exit_event(event_thread_exit) ||
      !drmgr_register_bb_app2app_event(event_bb_app2app, NULL) ||
      !drmgr_register_bb_instrumentation_event(NULL /*analysis_func*/, event_app_instruction, NULL) ||
      !drmgr_register_module_load_event(event_module_load))
    DR_ASSERT(false);

  the_client_id = id;
  the_mutex = dr_mutex_create();

  module_data_t* main_module = dr_get_main_module();
  DR_ASSERT(main_module);

  size_t next_run_offset = 0;
  size_t report_test_result_offset = 0;
  drsym_error_t status;
  status = drsym_lookup_symbol(main_module->full_path, "NextRun", &next_run_offset, DRSYM_DEFAULT_FLAGS);
  DR_ASSERT(status == DRSYM_SUCCESS);
  status =
      drsym_lookup_symbol(main_module->full_path, "ReportTestResult", &report_test_result_offset, DRSYM_DEFAULT_FLAGS);
  DR_ASSERT(status == DRSYM_SUCCESS);

  uintptr_t next_run_addr = reinterpret_cast<uintptr_t>(main_module->start) + next_run_offset;
  uintptr_t report_test_result_addr = reinterpret_cast<uintptr_t>(main_module->start) + report_test_result_offset;

  bool ok;
  ok = drwrap_replace_native(reinterpret_cast<app_pc>(next_run_addr),
                             reinterpret_cast<app_pc>(reinterpret_cast<void*>(WrapNextRun)), true, 0, NULL, false);
  DR_ASSERT(ok);
  ok = drwrap_replace_native(reinterpret_cast<app_pc>(report_test_result_addr),
                             reinterpret_cast<app_pc>(reinterpret_cast<void*>(WrapReportTestResult)), true, 0, NULL,
                             false);
  DR_ASSERT(ok);

  dr_free_module_data(main_module);

  the_tls_idx = drmgr_register_tls_field();
  DR_ASSERT(the_tls_idx != -1);
  /* The TLS field provided by DR cannot be directly accessed from the code cache.
   * For better performance, we allocate raw TLS so that we can directly
   * access and update it with a single instruction.
   */
  if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, TLS_OFFSET__COUNT, alignof(void*))) DR_ASSERT(false);

  dr_log(NULL, DR_LOG_ALL, 1, "Client 'runner' initializing\n");
}
