/* ******************************************************************************
 * Copyright (c) 2013-2018 Google, Inc.  All rights reserved.
 * Copyright (c) 2011 Massachusetts Institute of Technology  All rights reserved.
 * Copyright (c) 2008 VMware, Inc.  All rights reserved.
 * ******************************************************************************/

/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * * Redistributions of source code must retain the above copyright notice,
 *   this list of conditions and the following disclaimer.
 *
 * * Redistributions in binary form must reproduce the above copyright notice,
 *   this list of conditions and the following disclaimer in the documentation
 *   and/or other materials provided with the distribution.
 *
 * * Neither the name of Google, Inc. nor the names of its contributors may be
 *   used to endorse or promote products derived from this software without
 *   specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL GOOGLE, INC. OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 */

#include <stddef.h> /* for offsetof */
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

enum MemoryReferenceKind : uint16_t {
  REF_KIND_READ = 0,
  REF_KIND_WRITE = 1,
  REF_KIND_MEMORY_HINT = 2,

  // `MemoryReferenceKind` values which are `REF_KIND__COUNT` are opcodes.
  REF_KIND__COUNT
};

struct MemoryReference {
  MemoryReferenceKind type;
  uint16_t size;  // Size of memory reference, or instruction length.
  app_pc addr;    // Address of the memory reference, or instruction address.
};

// Maximum number of `MemoryReference` objects a buffer can have. It should be big enough to hold all entries between
// all clean calls.
static constexpr size_t kMemoryReferenceMaxCount = 4096;
static constexpr size_t kMemoryReferenceBufferSize = sizeof(MemoryReference) * 4096;

struct ThreadData {
  int thread_idx;
  bool entered_instrumentation;
  uint8_t* tls_segment_base;
  MemoryReference* buffer_base;
  uint64_t memory_reference_count;
  BufferedFileWriter writer;
};

static void* the_mutex;
static client_id_t the_client_id;
static uint64_t the_total_memory_reference_count;

static void* the_module_mutex;
static BufferedFileWriter the_module_writer;

static int volatile the_next_thread_idx;

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

// `Wrap*` functions.
static bool WrapInstrumenting() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  drwrap_replace_native_fini(drcontext);
  return data->entered_instrumentation;
}

static void WrapInstrumentationPause() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  DR_ASSERT(IS_INSTRUMENTING(data->tls_segment_base));
  IS_INSTRUMENTING(data->tls_segment_base) = 0;
  drwrap_replace_native_fini(drcontext);
}

static void WrapInstrumentationResume() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  DR_ASSERT(!IS_INSTRUMENTING(data->tls_segment_base));
  IS_INSTRUMENTING(data->tls_segment_base) = 1;
  drwrap_replace_native_fini(drcontext);
}

static bool WrapNextRun() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  bool was_instrumenting = data->entered_instrumentation;
  if (!was_instrumenting) {
    DR_ASSERT(IS_INSTRUMENTING(data->tls_segment_base) == 0);
    IS_INSTRUMENTING(data->tls_segment_base) = 1;
  }
  data->entered_instrumentation = true;
  drwrap_replace_native_fini(drcontext);
  return !was_instrumenting;
}

static void WrapRunDone() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  DR_ASSERT(IS_INSTRUMENTING(data->tls_segment_base));
  IS_INSTRUMENTING(data->tls_segment_base) = 0;
  drwrap_replace_native_fini(drcontext);
}

static int WrapThreadIdx() {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  drwrap_replace_native_fini(drcontext);
  return data->thread_idx;
}

static void WrapContiguousMemoryHint(void* ptr, int size) {
  void* drcontext = dr_get_current_drcontext();
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);

  // TODO: Lame assert.
  DR_ASSERT(size <= 65535);

  // TODO: We assume that we have enough space in buf ptr, and we probably do, but check this better.
  MemoryReference* current = BUF_PTR(data->tls_segment_base);
  current->type = REF_KIND_MEMORY_HINT;
  current->size = static_cast<uint16_t>(size);
  current->addr = reinterpret_cast<app_pc>(ptr);
  BUF_PTR(data->tls_segment_base) = current + 1;
  drwrap_replace_native_fini(drcontext);
}

static void Memtrace(void* drcontext) {
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  MemoryReference* buf_ptr = BUF_PTR(data->tls_segment_base);

  for (MemoryReference* mem_ref = (MemoryReference*)data->buffer_base; mem_ref < buf_ptr; mem_ref++) {
    data->writer.WriteUint16LE(mem_ref->type);
    data->writer.WriteUint16LE(mem_ref->size);
    data->writer.WriteUint64LE(reinterpret_cast<uint64_t>(reinterpret_cast<uintptr_t>(mem_ref->addr)));
    if (mem_ref->type != REF_KIND_READ && mem_ref->type != REF_KIND_WRITE && mem_ref->type != REF_KIND_MEMORY_HINT) {
      data->writer.WriteString(Wrap(decode_opcode_name(mem_ref->type)));
    } else {
      data->writer.WriteUint64LE(0);
    }
  }
  BUF_PTR(data->tls_segment_base) = data->buffer_base;
}

static void CleanCall(void) {
  void* drcontext = dr_get_current_drcontext();
  Memtrace(drcontext);
}

static void InsertLoadBufPtr(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t reg_ptr) {
  dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + TLS_OFFSET_BUF_PTR * sizeof(void*), reg_ptr);
}

static void InsertUpdateBufPtr(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t reg_ptr, int adjust) {
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_add(drcontext, opnd_create_reg(reg_ptr), OPND_CREATE_INT16(adjust)));
  dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + TLS_OFFSET_BUF_PTR * sizeof(void*), reg_ptr);
}

static void InsertLoadIsInstrumenting(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t reg_ptr) {
  dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + TLS_OFFSET_IS_INSTRUMENTING * sizeof(void*),
                         reg_ptr);
}

static void InsertSetIsInstrumenting(void* drcontext, instrlist_t* ilist, instr_t* where, uintptr_t value,
                                     reg_id_t scratch) {
  instrlist_insert_mov_immed_ptrsz(drcontext, value, opnd_create_reg(scratch), ilist, where, NULL, NULL);
  dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + TLS_OFFSET_IS_INSTRUMENTING * sizeof(void*),
                          scratch);
}

static void InsertSaveType(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t base, reg_id_t scratch,
                           ushort type) {
  scratch = reg_resize_to_opsz(scratch, OPSZ_2);
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch), OPND_CREATE_INT16(type)));
  instrlist_meta_preinsert(
      ilist, where,
      XINST_CREATE_store_2bytes(drcontext, OPND_CREATE_MEM16(base, offsetof(MemoryReference, type)),
                                opnd_create_reg(scratch)));
}

static void InsertSaveSize(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t base, reg_id_t scratch,
                           ushort size) {
  scratch = reg_resize_to_opsz(scratch, OPSZ_2);
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch), OPND_CREATE_INT16(size)));
  instrlist_meta_preinsert(
      ilist, where,
      XINST_CREATE_store_2bytes(drcontext, OPND_CREATE_MEM16(base, offsetof(MemoryReference, size)),
                                opnd_create_reg(scratch)));
}

static void InsertSavePc(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t base, reg_id_t scratch,
                         app_pc pc) {
  instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd_create_reg(scratch), ilist, where, NULL, NULL);
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(base, offsetof(MemoryReference, addr)),
                                              opnd_create_reg(scratch)));
}

static void InsertSaveAddress(void* drcontext, instrlist_t* ilist, instr_t* where, opnd_t ref, reg_id_t reg_ptr,
                              reg_id_t reg_addr) {
  bool ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_addr, reg_ptr);
  DR_ASSERT(ok);
  InsertLoadBufPtr(drcontext, ilist, where, reg_ptr);
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(reg_ptr, offsetof(MemoryReference, addr)),
                                              opnd_create_reg(reg_addr)));
}

static void InsertCmpWithPtr(void* drcontext, instrlist_t* ilist, instr_t* where, uintptr_t value, reg_id_t reg,
                             reg_id_t scratch) {
  instrlist_insert_mov_immed_ptrsz(drcontext, value, opnd_create_reg(scratch), ilist, where, NULL, NULL);
  instrlist_meta_preinsert(ilist, where, XINST_CREATE_cmp(drcontext, opnd_create_reg(reg), opnd_create_reg(scratch)));
}

static void InsertSkipIfNotInstrumenting(void* drcontext, instrlist_t* ilist, instr_t* where, instr_t* label,
                                         reg_id_t scratch) {
  InsertLoadIsInstrumenting(drcontext, ilist, where, scratch);
  instrlist_meta_preinsert(ilist, where, XINST_CREATE_cmp(drcontext, opnd_create_reg(scratch), OPND_CREATE_INT8(0)));
  instrlist_meta_preinsert(ilist, where, XINST_CREATE_jump_cond(drcontext, DR_PRED_EQ, opnd_create_instr(label)));
}

static void InstrumentInstruction(void* drcontext, instrlist_t* ilist, instr_t* where, instr_t* instr) {
  // We need two scratch registers. Backup register state and aflags.
  reg_id_t reg_ptr, reg_tmp;
  // We don't want to predicate this, because an instruction fetch always occurs.
  instrlist_set_auto_predicate(ilist, DR_PRED_NONE);
  if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
      drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) != DRREG_SUCCESS ||
      drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
    DR_ASSERT(false);
    return;
  }

  instr_t* label_skip = INSTR_CREATE_label(drcontext);
  InsertSkipIfNotInstrumenting(drcontext, ilist, where, label_skip, reg_tmp);

  InsertLoadBufPtr(drcontext, ilist, where, reg_ptr);
  InsertSaveType(drcontext, ilist, where, reg_ptr, reg_tmp, (ushort)instr_get_opcode(instr));
  InsertSaveSize(drcontext, ilist, where, reg_ptr, reg_tmp, (ushort)instr_length(drcontext, instr));
  InsertSavePc(drcontext, ilist, where, reg_ptr, reg_tmp, instr_get_app_pc(instr));
  InsertUpdateBufPtr(drcontext, ilist, where, reg_ptr, sizeof(MemoryReference));

  instrlist_meta_preinsert(ilist, where, label_skip);

  // Restore scratch registers and aflags.
  if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
      drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS ||
      drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
    DR_ASSERT(false);
  instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
}

static void InstrumentMemoryReference(void* drcontext, instrlist_t* ilist, instr_t* where, opnd_t ref, bool write) {
  // We need two scratch registers. Backup register state and aflags.
  reg_id_t reg_ptr, reg_tmp;
  if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
      drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) != DRREG_SUCCESS ||
      drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
    DR_ASSERT(false);
    return;
  }

  instr_t* label_skip = INSTR_CREATE_label(drcontext);
  InsertSkipIfNotInstrumenting(drcontext, ilist, where, label_skip, reg_tmp);

  InsertSaveAddress(drcontext, ilist, where, ref, reg_ptr, reg_tmp);
  InsertSaveType(drcontext, ilist, where, reg_ptr, reg_tmp, write ? REF_KIND_WRITE : REF_KIND_READ);
  InsertSaveSize(drcontext, ilist, where, reg_ptr, reg_tmp, (ushort)drutil_opnd_mem_size_in_bytes(ref, where));
  InsertUpdateBufPtr(drcontext, ilist, where, reg_ptr, sizeof(MemoryReference));

  instrlist_meta_preinsert(ilist, where, label_skip);

  // Restore scratch registers and aflags.
  if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
      drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS ||
      drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
    DR_ASSERT(false);
}

static dr_emit_flags_t EventAppInstruction(void* drcontext, void* tag, instrlist_t* bb, instr_t* where, bool for_trace,
                                           bool translating, void* user_data) {
  instr_t* instr_fetch = drmgr_orig_app_instr_for_fetch(drcontext);
  if (instr_fetch) {
    DR_ASSERT(instr_is_app(instr_fetch));
    if (instr_reads_memory(instr_fetch) || instr_writes_memory(instr_fetch) || instr_is_syscall(instr_fetch)) {
      InstrumentInstruction(drcontext, bb, where, instr_fetch);
    }
  }

  instr_t* instr_operands = drmgr_orig_app_instr_for_operands(drcontext);
  if (!instr_operands) return DR_EMIT_DEFAULT;
  DR_ASSERT(instr_is_app(instr_operands));

  if (instr_reads_memory(instr_operands) || instr_writes_memory(instr_operands)) {
    for (int i = 0; i < instr_num_srcs(instr_operands); i++) {
      const opnd_t src = instr_get_src(instr_operands, i);
      if (opnd_is_memory_reference(src)) {
        InstrumentMemoryReference(drcontext, bb, where, src, false);
      }
    }

    for (int i = 0; i < instr_num_dsts(instr_operands); i++) {
      const opnd_t dst = instr_get_dst(instr_operands, i);
      if (opnd_is_memory_reference(dst)) {
        InstrumentMemoryReference(drcontext, bb, where, dst, true);
      }
    }

    // Insert code to call `CleanCall` for processing the buffer.
    if (/* XXX i#1698: there are constraints for code between ldrex/strex pairs,
         * so we minimize the instrumentation in between by skipping the clean call.
         * As we're only inserting instrumentation on a memory reference, and the
         * app should be avoiding memory accesses in between the ldrex...strex,
         * the only problematic point should be before the strex.
         * However, there is still a chance that the instrumentation code may clear the
         * exclusive monitor state.
         * Using a fault to handle a full buffer should be more robust, and the
         * forthcoming buffer filling API (i#513) will provide that.
         */
        IF_AARCHXX_ELSE(!instr_is_exclusive_store(instr_operands), true))
      dr_insert_clean_call(drcontext, bb, where, (void*)CleanCall, false, 0);
  }

  return DR_EMIT_DEFAULT;
}

// Original transfromation from
// https://github.com/DynamoRIO/dynamorio/blob/7db4ca97d8bea55345aaa6ee3d66bbbd13ee6496/api/samples/memtrace_simple.c
// Original comment:
//  We transform string loops into regular loops so we can more easily
//  monitor every memory reference they make.
static dr_emit_flags_t EventBbApp2App(void* drcontext, void* tag, instrlist_t* bb, bool for_trace, bool translating) {
  if (!drutil_expand_rep_string(drcontext, bb)) {
    DR_ASSERT(false);
    // In release build, carry on: we'll just miss per-iter references.
  }
  if (!drx_expand_scatter_gather(drcontext, bb, NULL)) {
    DR_ASSERT(false);
  }
  return DR_EMIT_DEFAULT;
}

static void EventThreadInit(void* drcontext) {
  ThreadData* data = (ThreadData*)dr_thread_alloc(drcontext, sizeof(ThreadData));
  memset(data, 0, sizeof(*data));
  DR_ASSERT(data != NULL);
  drmgr_set_tls_field(drcontext, the_tls_idx, data);

  // Keep `tls_segment_base` in a per-thread data structure so we can get the TLS slot and find where the pointer points
  // to in the buffer.
  data->thread_idx = dr_atomic_add32_return_sum(&the_next_thread_idx, 1) - 1;
  data->tls_segment_base = (uint8_t*)dr_get_dr_segment_base(tls_seg);
  data->buffer_base =
      (MemoryReference*)dr_raw_mem_alloc(kMemoryReferenceBufferSize, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
  DR_ASSERT(data->tls_segment_base != NULL && data->buffer_base != NULL);
  BUF_PTR(data->tls_segment_base) = data->buffer_base;
  IS_INSTRUMENTING(data->tls_segment_base) = 0;
  data->memory_reference_count = 0;

  file_t file = OpenUniqueFile(Wrap("./collect"), Wrap("test"), Wrap("bin"), false, true);
  BufferedFileWriter::Make(&data->writer, drcontext, file, 64 * 1024 * 1024);
}

static void EventModuleLoad(void* drcontext, const module_data_t* info, bool loaded) {
  dr_mutex_lock(the_module_mutex);
  Defer(dr_mutex_unlock(the_module_mutex));

  the_module_writer.WriteUint8LE(loaded ? 1 : 0);
  the_module_writer.WriteUint64LE(reinterpret_cast<uintptr_t>(info->entry_point));
  the_module_writer.WriteUint64LE(reinterpret_cast<uintptr_t>(info->preferred_base));
  the_module_writer.WriteUint64LE(reinterpret_cast<uintptr_t>(info->start));
  the_module_writer.WriteUint64LE(reinterpret_cast<uintptr_t>(info->end));
  the_module_writer.WriteString(Wrap(dr_module_preferred_name(info)));
  the_module_writer.WriteString(Wrap(info->full_path));
}

static void EventThreadExit(void* drcontext) {
  // Dump remaining entries.
  Memtrace(drcontext);
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  dr_mutex_lock(the_mutex);
  the_total_memory_reference_count += data->memory_reference_count;
  uint64_t count = reinterpret_cast<uint64_t>(IS_INSTRUMENTING(data->tls_segment_base));
  dr_mutex_unlock(the_mutex);
  data->writer.FlushAndDestroy();

  dr_raw_mem_free(data->buffer_base, kMemoryReferenceBufferSize);
  dr_thread_free(drcontext, data, sizeof(ThreadData));
}

static void EventExit() {
  dr_log(NULL, DR_LOG_ALL, 1, "Client 'collector' num refs seen: %llu\n", the_total_memory_reference_count);
  if (!dr_raw_tls_cfree(tls_offs, TLS_OFFSET__COUNT)) DR_ASSERT(false);

  if (!drmgr_unregister_tls_field(the_tls_idx) || !drmgr_unregister_thread_init_event(EventThreadInit) ||
      !drmgr_unregister_thread_exit_event(EventThreadExit) || !drmgr_unregister_bb_app2app_event(EventBbApp2App) ||
      !drmgr_unregister_bb_insertion_event(EventAppInstruction) ||
      !drmgr_unregister_module_load_event(EventModuleLoad) || drreg_exit() != DRREG_SUCCESS)
    DR_ASSERT(false);

  the_module_writer.FlushAndDestroy();
  dr_mutex_destroy(the_mutex);
  dr_mutex_destroy(the_module_mutex);
  drmgr_exit();
  drutil_exit();
  drwrap_exit();
  drx_exit();
  drsym_exit();

  // printf("we done\n");
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  // We need 2 reg slots beyond drreg's eflags slots == 3 slots in total.
  drreg_options_t ops = {sizeof(ops), 3, false};
  dr_set_client_name("collector", "");

  if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drutil_init() || !drwrap_init() || !drx_init() ||
      drsym_init(0) != DRSYM_SUCCESS)
    DR_ASSERT(false);

  dr_register_exit_event(EventExit);
  if (!drmgr_register_thread_init_event(EventThreadInit) || !drmgr_register_thread_exit_event(EventThreadExit) ||
      !drmgr_register_bb_app2app_event(EventBbApp2App, NULL) ||
      !drmgr_register_bb_instrumentation_event(NULL /*analysis_func*/, EventAppInstruction, NULL) ||
      !drmgr_register_module_load_event(EventModuleLoad))
    DR_ASSERT(false);

  the_client_id = id;
  the_mutex = dr_mutex_create();
  the_module_mutex = dr_mutex_create();

  module_data_t* main_module = dr_get_main_module();
  DR_ASSERT(main_module);

  auto replace_native = [main_module](const char* name, auto* replace_with) {
    size_t offset = 0;
    drsym_error_t status = drsym_lookup_symbol(main_module->full_path, name, &offset, DRSYM_DEFAULT_FLAGS);
    DR_ASSERT(status == DRSYM_SUCCESS);

    uintptr_t addr = reinterpret_cast<uintptr_t>(main_module->start) + offset;
    bool ok =
        drwrap_replace_native(reinterpret_cast<app_pc>(addr),
                              reinterpret_cast<app_pc>(reinterpret_cast<void*>(replace_with)), true, 0, NULL, false);
  };

  replace_native("Instrumenting", WrapInstrumenting);
  replace_native("InstrumentationPause", WrapInstrumentationPause);
  replace_native("InstrumentationResume", WrapInstrumentationResume);
  // `InstrumentingWaitForAll` in userspace.
  replace_native("NextRun", WrapNextRun);
  replace_native("RunDone", WrapRunDone);
  replace_native("ThreadIdx", WrapThreadIdx);
  // `MustAlways` already noop.
  // `MustAtleastOnce` already noop.
  replace_native("ContiguousMemoryHint", WrapContiguousMemoryHint);

  dr_free_module_data(main_module);

  file_t module_file = OpenUniqueFile(Wrap("./collect"), Wrap("module"), Wrap("module"), false, true);
  BufferedFileWriter::Make(&the_module_writer, nullptr, module_file, 1024);

  the_tls_idx = drmgr_register_tls_field();
  DR_ASSERT(the_tls_idx != -1);
  // The TLS field provided by DR cannot be directly accessed from the code cache. For better performance, we allocate
  // raw TLS so that we can directly access and update it with a single instruction.
  if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, TLS_OFFSET__COUNT, alignof(void*))) DR_ASSERT(false);

  dr_log(NULL, DR_LOG_ALL, 1, "collector");
}
