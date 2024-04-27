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
#include "drx.h"

#include "common.h"

using namespace app;

enum MemoryReferenceKind : uint16_t {
  REF_KIND_READ = 0,
  REF_KIND_WRITE = 1,
};

struct MemoryReference {
  MemoryReferenceKind type; /* r(0), w(1), or opcode (assuming 0/1 are invalid opcode) */
  uint16_t size;            /* mem ref size or instr length */
  app_pc addr;              /* mem ref addr or instr pc */
};

/* Max number of mem_ref a buffer can have. It should be big enough
 * to hold all entries between clean calls.
 */
#define MAX_NUM_MEM_REFS 4096
/* The maximum size of buffer for holding mem_refs. */
#define MEM_BUF_SIZE (sizeof(MemoryReference) * MAX_NUM_MEM_REFS)

struct ThreadData {
  uint8_t* seg_base;
  MemoryReference* buf_base;
  uint64_t num_refs;
  BufferedFileWriter writer;
};

static void* the_mutex;
static client_id_t the_client_id;
static uint64_t the_total_memory_reference_count;

static void* the_module_mutex;
static BufferedFileWriter the_module_writer;

uintptr_t the_begin_instrumentation_address;
uintptr_t the_end_instrumentation_address;

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

static void memtrace(void* drcontext) {
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  MemoryReference* buf_ptr = BUF_PTR(data->seg_base);

  for (MemoryReference* mem_ref = (MemoryReference*)data->buf_base; mem_ref < buf_ptr; mem_ref++) {
    data->writer.WriteUint16LE(mem_ref->type);
    data->writer.WriteUint16LE(mem_ref->size);
    data->writer.WriteUint64LE(reinterpret_cast<uint64_t>(reinterpret_cast<uintptr_t>(mem_ref->addr)));
    if (mem_ref->type != REF_KIND_READ && mem_ref->type != REF_KIND_WRITE) {
      data->writer.WriteString(Wrap(decode_opcode_name(mem_ref->type)));
    } else {
      data->writer.WriteUint64LE(0);
    }
  }
  BUF_PTR(data->seg_base) = data->buf_base;
}

static void clean_call(void) {
  void* drcontext = dr_get_current_drcontext();
  memtrace(drcontext);
}

static void insert_load_buf_ptr(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t reg_ptr) {
  dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + TLS_OFFSET_BUF_PTR * sizeof(void*), reg_ptr);
}

static void insert_update_buf_ptr(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t reg_ptr, int adjust) {
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_add(drcontext, opnd_create_reg(reg_ptr), OPND_CREATE_INT16(adjust)));
  dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + TLS_OFFSET_BUF_PTR * sizeof(void*), reg_ptr);
}

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

static void insert_save_type(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t base, reg_id_t scratch,
                             ushort type) {
  scratch = reg_resize_to_opsz(scratch, OPSZ_2);
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch), OPND_CREATE_INT16(type)));
  instrlist_meta_preinsert(
      ilist, where,
      XINST_CREATE_store_2bytes(drcontext, OPND_CREATE_MEM16(base, offsetof(MemoryReference, type)),
                                opnd_create_reg(scratch)));
}

static void insert_save_size(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t base, reg_id_t scratch,
                             ushort size) {
  scratch = reg_resize_to_opsz(scratch, OPSZ_2);
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch), OPND_CREATE_INT16(size)));
  instrlist_meta_preinsert(
      ilist, where,
      XINST_CREATE_store_2bytes(drcontext, OPND_CREATE_MEM16(base, offsetof(MemoryReference, size)),
                                opnd_create_reg(scratch)));
}

static void insert_save_pc(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t base, reg_id_t scratch,
                           app_pc pc) {
  instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd_create_reg(scratch), ilist, where, NULL, NULL);
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(base, offsetof(MemoryReference, addr)),
                                              opnd_create_reg(scratch)));
}

static void insert_save_addr(void* drcontext, instrlist_t* ilist, instr_t* where, opnd_t ref, reg_id_t reg_ptr,
                             reg_id_t reg_addr) {
  /* we use reg_ptr as scratch to get addr */
  bool ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_addr, reg_ptr);
  DR_ASSERT(ok);
  insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);
  instrlist_meta_preinsert(ilist, where,
                           XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(reg_ptr, offsetof(MemoryReference, addr)),
                                              opnd_create_reg(reg_addr)));
}

static void insert_cmp_with_ptr(void* drcontext, instrlist_t* ilist, instr_t* where, uintptr_t value, reg_id_t reg,
                                reg_id_t scratch) {
  instrlist_insert_mov_immed_ptrsz(drcontext, value, opnd_create_reg(scratch), ilist, where, NULL, NULL);
  instrlist_meta_preinsert(ilist, where, XINST_CREATE_cmp(drcontext, opnd_create_reg(reg), opnd_create_reg(scratch)));
}

static void insert_skip_if_not_instrumenting(void* drcontext, instrlist_t* ilist, instr_t* where, instr_t* label,
                                             reg_id_t scratch) {
  insert_load_is_instrumenting(drcontext, ilist, where, scratch);
  instrlist_meta_preinsert(ilist, where, XINST_CREATE_cmp(drcontext, opnd_create_reg(scratch), OPND_CREATE_INT8(0)));
  instrlist_meta_preinsert(ilist, where, XINST_CREATE_jump_cond(drcontext, DR_PRED_EQ, opnd_create_instr(label)));
}

/* insert inline code to add an instruction entry into the buffer */
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

  instr_t* label_skip = INSTR_CREATE_label(drcontext);
  insert_skip_if_not_instrumenting(drcontext, ilist, where, label_skip, reg_tmp);

  insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);
  insert_save_type(drcontext, ilist, where, reg_ptr, reg_tmp, (ushort)instr_get_opcode(instr));
  insert_save_size(drcontext, ilist, where, reg_ptr, reg_tmp, (ushort)instr_length(drcontext, instr));
  insert_save_pc(drcontext, ilist, where, reg_ptr, reg_tmp, instr_get_app_pc(instr));
  insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(MemoryReference));

  instrlist_meta_preinsert(ilist, where, label_skip);

  /* Restore scratch registers */
  if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
      drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS ||
      drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
    DR_ASSERT(false);
  instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
}

/* insert inline code to add a memory reference info entry into the buffer */
static void instrument_mem(void* drcontext, instrlist_t* ilist, instr_t* where, opnd_t ref, bool write) {
  /* We need two scratch registers */
  reg_id_t reg_ptr, reg_tmp;
  if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
      drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) != DRREG_SUCCESS ||
      drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
    DR_ASSERT(false);
    return;
  }

  instr_t* label_skip = INSTR_CREATE_label(drcontext);
  insert_skip_if_not_instrumenting(drcontext, ilist, where, label_skip, reg_tmp);

  /* save_addr should be called first as reg_ptr or reg_tmp maybe used in ref */
  insert_save_addr(drcontext, ilist, where, ref, reg_ptr, reg_tmp);
  insert_save_type(drcontext, ilist, where, reg_ptr, reg_tmp, write ? REF_KIND_WRITE : REF_KIND_READ);
  insert_save_size(drcontext, ilist, where, reg_ptr, reg_tmp, (ushort)drutil_opnd_mem_size_in_bytes(ref, where));
  insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(MemoryReference));

  instrlist_meta_preinsert(ilist, where, label_skip);

  /* Restore scratch registers */
  if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
      drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS ||
      drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
    DR_ASSERT(false);
}

static void instrument_control_transfer_instr(void* drcontext, instrlist_t* ilist, instr_t* where, opnd_t target) {
  /* We need two scratch registers */
  reg_id_t reg_ptr, reg_addr;
  if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
      drreg_reserve_register(drcontext, ilist, where, NULL, &reg_addr) != DRREG_SUCCESS ||
      drreg_reserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS) {
    DR_ASSERT(false);
    return;
  }

  if (opnd_is_memory_reference(target)) {
    // We use reg_ptr as scratch to get addr.
    bool ok = drutil_insert_get_mem_addr(drcontext, ilist, where, target, reg_addr, reg_ptr);
    DR_ASSERT(ok);

    instr_t* label_begin_instrumentation = INSTR_CREATE_label(drcontext);
    instr_t* label_end_instrumentation = INSTR_CREATE_label(drcontext);
    instr_t* label_skip = INSTR_CREATE_label(drcontext);

    // Load `the_begin_instrumentation_address` into `reg_ptr` (which we are currently using as a scratch register).
    insert_cmp_with_ptr(drcontext, ilist, where, the_begin_instrumentation_address, reg_addr, reg_ptr);
    instrlist_meta_preinsert(
        ilist, where, XINST_CREATE_jump_cond(drcontext, DR_PRED_EQ, opnd_create_instr(label_begin_instrumentation)));

    insert_cmp_with_ptr(drcontext, ilist, where, the_end_instrumentation_address, reg_addr, reg_ptr);
    instrlist_meta_preinsert(
        ilist, where, XINST_CREATE_jump_cond(drcontext, DR_PRED_EQ, opnd_create_instr(label_end_instrumentation)));

    instrlist_meta_preinsert(ilist, where, XINST_CREATE_jump(drcontext, opnd_create_instr(label_skip)));

    instrlist_meta_preinsert(ilist, where, label_begin_instrumentation);
    insert_set_is_instrumenting(drcontext, ilist, where, 1, reg_ptr);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_jump(drcontext, opnd_create_instr(label_skip)));

    instrlist_meta_preinsert(ilist, where, label_end_instrumentation);
    insert_set_is_instrumenting(drcontext, ilist, where, 0, reg_ptr);

    instrlist_meta_preinsert(ilist, where, label_skip);
  } else if (opnd_is_pc(target)) {
    uintptr_t address = reinterpret_cast<uintptr_t>(opnd_get_pc(target));
    if (address == the_begin_instrumentation_address) {
      insert_set_is_instrumenting(drcontext, ilist, where, 1, reg_ptr);
    } else if (address == the_end_instrumentation_address) {
      insert_set_is_instrumenting(drcontext, ilist, where, 0, reg_ptr);
    }
  } else if (opnd_is_immed(target)) {
    uint64_t address = opnd_get_immed_int64(target);
    if (address == the_begin_instrumentation_address) {
      insert_set_is_instrumenting(drcontext, ilist, where, 1, reg_ptr);
    } else if (address == the_end_instrumentation_address) {
      insert_set_is_instrumenting(drcontext, ilist, where, 0, reg_ptr);
    }
  } else {
    DR_ASSERT(false);
  }

  /* Restore scratch registers */
  if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
      drreg_unreserve_register(drcontext, ilist, where, reg_addr) != DRREG_SUCCESS ||
      drreg_unreserve_aflags(drcontext, ilist, where) != DRREG_SUCCESS)
    DR_ASSERT(false);
}

/* For each memory reference app instr, we insert inline code to fill the buffer
 * with an instruction entry and memory reference entries.
 */
static dr_emit_flags_t event_app_instruction(void* drcontext, void* tag, instrlist_t* bb, instr_t* where,
                                             bool for_trace, bool translating, void* user_data) {
  /* Insert code to add an entry for each app instruction. */
  /* Use the drmgr_orig_app_instr_* interface to properly handle our own use
   * of drutil_expand_rep_string() and drx_expand_scatter_gather() (as well
   * as another client/library emulating the instruction stream).
   */

  // If it happens that we can call `instrument_control_transfer_instr` for this instruction, `instrument_instr` must be
  // called after it. Wrap `instrument_control_transfer_instr` and either call it `instrument_control_transfer_instr`,
  // or immediately if ``instrument_control_transfer_instr` can't be called here.
  auto maybe_instrument_instr = [&]() {
    instr_t* instr_fetch = drmgr_orig_app_instr_for_fetch(drcontext);
    if (!instr_fetch) return;
    DR_ASSERT(instr_is_app(instr_fetch));
    if (instr_reads_memory(instr_fetch) || instr_writes_memory(instr_fetch)) {
      instrument_instr(drcontext, bb, where, instr_fetch);
    }
  };

  /* Insert code to add an entry for each memory reference opnd. */
  instr_t* instr_operands = drmgr_orig_app_instr_for_operands(drcontext);
  if (instr_operands == NULL) {
    maybe_instrument_instr();
    return DR_EMIT_DEFAULT;
  }
  DR_ASSERT(instr_is_app(instr_operands));

  if (instr_is_cti(instr_operands)) {
    const opnd_t target = instr_get_target(instr_operands);
    if (opnd_is_memory_reference(target) || opnd_is_pc(target) || opnd_is_immed(target)) {
      instrument_control_transfer_instr(drcontext, bb, where, target);
    }
  }

  maybe_instrument_instr();

  if (instr_reads_memory(instr_operands) || instr_writes_memory(instr_operands)) {
    for (int i = 0; i < instr_num_srcs(instr_operands); i++) {
      const opnd_t src = instr_get_src(instr_operands, i);
      if (opnd_is_memory_reference(src)) {
        instrument_mem(drcontext, bb, where, src, false);
      }
    }

    for (int i = 0; i < instr_num_dsts(instr_operands); i++) {
      const opnd_t dst = instr_get_dst(instr_operands, i);
      if (opnd_is_memory_reference(dst)) {
        instrument_mem(drcontext, bb, where, dst, true);
      }
    }

    /* insert code to call clean_call for processing the buffer */
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
      dr_insert_clean_call(drcontext, bb, where, (void*)clean_call, false, 0);
  }

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
  drmgr_set_tls_field(drcontext, the_tls_idx, data);

  /* Keep seg_base in a per-thread data structure so we can get the TLS
   * slot and find where the pointer points to in the buffer.
   */
  data->seg_base = (uint8_t*)dr_get_dr_segment_base(tls_seg);
  data->buf_base = (MemoryReference*)dr_raw_mem_alloc(MEM_BUF_SIZE, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
  DR_ASSERT(data->seg_base != NULL && data->buf_base != NULL);
  /* put buf_base to TLS as starting buf_ptr */
  BUF_PTR(data->seg_base) = data->buf_base;
  IS_INSTRUMENTING(data->seg_base) = 0;

  data->num_refs = 0;

  file_t file = OpenUniqueFile(drcontext, the_client_id, Wrap("test"), Wrap("bin"), false, true);
  BufferedFileWriter::Make(&data->writer, drcontext, file, 64 * 1024 * 1024);
}

static void event_module_load(void* drcontext, const module_data_t* info, bool loaded) {
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

static void event_thread_exit(void* drcontext) {
  memtrace(drcontext); /* dump any remaining buffer entries */
  ThreadData* data = (ThreadData*)drmgr_get_tls_field(drcontext, the_tls_idx);
  dr_mutex_lock(the_mutex);
  the_total_memory_reference_count += data->num_refs;
  uint64_t count = reinterpret_cast<uint64_t>(IS_INSTRUMENTING(data->seg_base));
  // printf("FUNCTION CALL COUNT: %lu\n", count);
  dr_mutex_unlock(the_mutex);
  data->writer.FlushAndDestroy();

  dr_raw_mem_free(data->buf_base, MEM_BUF_SIZE);
  dr_thread_free(drcontext, data, sizeof(ThreadData));
}

static void event_exit(void) {
  dr_log(NULL, DR_LOG_ALL, 1, "Client 'memtrace' num refs seen: %llu\n", the_total_memory_reference_count);
  if (!dr_raw_tls_cfree(tls_offs, TLS_OFFSET__COUNT)) DR_ASSERT(false);

  if (!drmgr_unregister_tls_field(the_tls_idx) || !drmgr_unregister_thread_init_event(event_thread_init) ||
      !drmgr_unregister_thread_exit_event(event_thread_exit) || !drmgr_unregister_bb_app2app_event(event_bb_app2app) ||
      !drmgr_unregister_bb_insertion_event(event_app_instruction) ||
      !drmgr_unregister_module_load_event(event_module_load) || drreg_exit() != DRREG_SUCCESS)
    DR_ASSERT(false);

  the_module_writer.FlushAndDestroy();
  dr_mutex_destroy(the_mutex);
  dr_mutex_destroy(the_module_mutex);
  drutil_exit();
  drmgr_exit();
  drx_exit();
  drsym_exit();

  // printf("we done\n");
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
  drreg_options_t ops = {sizeof(ops), 3, false};
  dr_set_client_name("DynamoRIO Sample Client 'memtrace'", "http://dynamorio.org/issues");

  if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drutil_init() || !drx_init() ||
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
  the_module_mutex = dr_mutex_create();

  file_t module_file = OpenUniqueFile(nullptr, the_client_id, Wrap("module"), Wrap("module"), false, true);
  BufferedFileWriter::Make(&the_module_writer, nullptr, module_file, 1024);

  module_data_t* main_module = dr_get_main_module();
  DR_ASSERT(main_module);

  size_t begin_instrumentation_address = 0;
  size_t end_instrumentation_address = 0;
  drsym_error_t status;
  status = drsym_lookup_symbol(main_module->full_path, "BeginInstrumentation", &begin_instrumentation_address,
                               DRSYM_DEFAULT_FLAGS);
  DR_ASSERT(status == DRSYM_SUCCESS);
  status = drsym_lookup_symbol(main_module->full_path, "EndInstrumentation", &end_instrumentation_address,
                               DRSYM_DEFAULT_FLAGS);
  DR_ASSERT(status == DRSYM_SUCCESS);

  the_begin_instrumentation_address = reinterpret_cast<uintptr_t>(begin_instrumentation_address + main_module->start);
  the_end_instrumentation_address = reinterpret_cast<uintptr_t>(end_instrumentation_address + main_module->start);

  // printf("BeginInstrumentation: %p\n", reinterpret_cast<void*>(the_begin_instrumentation_address));
  // printf("EndInstrumentation: %p\n", reinterpret_cast<void*>(the_end_instrumentation_address));

  dr_free_module_data(main_module);

  the_tls_idx = drmgr_register_tls_field();
  DR_ASSERT(the_tls_idx != -1);
  /* The TLS field provided by DR cannot be directly accessed from the code cache.
   * For better performance, we allocate raw TLS so that we can directly
   * access and update it with a single instruction.
   */
  if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, TLS_OFFSET__COUNT, alignof(void*))) DR_ASSERT(false);

  /* make it easy to tell, by looking at log file, which client executed */
  dr_log(NULL, DR_LOG_ALL, 1, "Client 'memtrace' initializing\n");
}
