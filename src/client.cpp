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
#include "drutil.h"
#include "drx.h"

#include "common.h"

namespace app {

void test(void *drcontext) {
  String a = Wrap("abc");
  String b = Wrap("123");
  String c = Wrap("xyz");
  String d = ConcatenateArrays(drcontext, a, b, c);
  printf("%.*s\n", StringArgs(d));
  return;

  const char* path = "/home/gabriel/dipl/foo.bin";
  file_t file = dr_open_file(path, DR_FILE_WRITE_OVERWRITE | DR_FILE_ALLOW_LARGE);
  DR_ASSERT(file != INVALID_FILE);

  BufferedFileWriter writer;
  BufferedFileWriter::Make(&writer, drcontext, file, 53);

  for (uint32_t i = 0; i < 100; ++i) {
    writer.WriteUint16LE(i);
    writer.WriteUint32LE(i);
  }

  writer.FlushAndDestroy();

  file = dr_open_file(path, DR_FILE_READ | DR_FILE_ALLOW_LARGE);
  DR_ASSERT(file != INVALID_FILE);

  BufferedFileReader reader;
  BufferedFileReader::Make(&reader, drcontext, file, 28);

  uint16_t value;
  while (reader.ReadUint16LE(&value)) {
    uint32_t value2;
    bool ok = reader.ReadUint32LE(&value2);
    DR_ASSERT(ok);
    printf("!!! %d %d\n", value, value2);
  }

  reader.Destroy();
}

}  // namespace app

using namespace app;

#define BUFFER_SIZE_ELEMENTS(a) (sizeof(a) / sizeof((a)[0]))
#define NULL_TERMINATE_BUFFER(a) ((a)[BUFFER_SIZE_ELEMENTS(a) - 1] = '\0')

#define SHOW_RESULTS 1
#define DISPLAY_STRING(str) printf("%s\n", (str))

file_t log_file_open(client_id_t id, void* drcontext, const char* path, const char* name, uint flags) {
  file_t log;
  char log_dir[MAXIMUM_PATH];
  char buf[MAXIMUM_PATH];
  size_t len;
  char* dirsep;

  DR_ASSERT(name != NULL);
  len = dr_snprintf(log_dir, BUFFER_SIZE_ELEMENTS(log_dir), "%s", path == NULL ? dr_get_client_path(id) : path);
  DR_ASSERT(len > 0);
  NULL_TERMINATE_BUFFER(log_dir);
  dirsep = log_dir + len - 1;
  if (path == NULL /* removing client lib */ ||
      /* path does not have a trailing / and is too large to add it */
      (*dirsep != '/' && len == BUFFER_SIZE_ELEMENTS(log_dir) - 1)) {
    for (dirsep = log_dir + len; *dirsep != '/'; dirsep--) DR_ASSERT(dirsep > log_dir);
  }
  /* remove trailing / if necessary */
  if (*dirsep == '/')
    *dirsep = 0;
  else if (sizeof(log_dir) > (dirsep + 1 - log_dir) / sizeof(log_dir[0]))
    *(dirsep + 1) = 0;
  NULL_TERMINATE_BUFFER(log_dir);
  /* we do not need call drx_init before using drx_open_unique_appid_file */
  log = drx_open_unique_appid_file(log_dir, dr_get_process_id(), name, "log", flags, buf, BUFFER_SIZE_ELEMENTS(buf));
  if (log != INVALID_FILE) {
    char msg[MAXIMUM_PATH];
    len = dr_snprintf(msg, BUFFER_SIZE_ELEMENTS(msg), "Data file %s created", buf);
    DR_ASSERT(len > 0);
    NULL_TERMINATE_BUFFER(msg);
    dr_log(drcontext, DR_LOG_ALL, 1, "%s", msg);
#ifdef SHOW_RESULTS
    DISPLAY_STRING(msg);
#endif
  }
  return log;
}

void log_file_close(file_t log) { dr_close_file(log); }

FILE* log_stream_from_file(file_t f) { return fdopen(f, "w"); }

void log_stream_close(FILE* f) { fclose(f); /* closes underlying fd too for all platforms */ }

enum {
  REF_TYPE_READ = 0,
  REF_TYPE_WRITE = 1,
};
/* Each mem_ref_t is a <type, size, addr> entry representing a memory reference
 * instruction or the reference information, e.g.:
 * - mem ref instr: { type = 42 (call), size = 5, addr = 0x7f59c2d002d3 }
 * - mem ref info:  { type = 1 (write), size = 8, addr = 0x7ffeacab0ec8 }
 */
typedef struct _mem_ref_t {
  ushort type; /* r(0), w(1), or opcode (assuming 0/1 are invalid opcode) */
  ushort size; /* mem ref size or instr length */
  app_pc addr; /* mem ref addr or instr pc */
} mem_ref_t;

/* Max number of mem_ref a buffer can have. It should be big enough
 * to hold all entries between clean calls.
 */
#define MAX_NUM_MEM_REFS 4096
/* The maximum size of buffer for holding mem_refs. */
#define MEM_BUF_SIZE (sizeof(mem_ref_t) * MAX_NUM_MEM_REFS)

/* thread private log file and counter */

struct ThreadUserdata {};

typedef struct {
  byte* seg_base;
  mem_ref_t* buf_base;
  file_t log;
  FILE* logf;
  uint64 num_refs;

  BufferedFileWriter writer;
} per_thread_t;

static client_id_t client_id;
static void* mutex;        /* for multithread support */
static uint64 num_refs;    /* keep a global memory reference count */
static bool log_to_stderr; /* for testing */

/* Allocated TLS slot offsets */
enum {
  MEMTRACE_TLS_OFFS_BUF_PTR,
  MEMTRACE_TLS_COUNT, /* total number of TLS slots allocated */
};
static reg_id_t tls_seg;
static uint tls_offs;
static int tls_idx;
#define TLS_SLOT(tls_base, enum_val) (void**)((byte*)(tls_base) + tls_offs + (enum_val))
#define BUF_PTR(tls_base) *(mem_ref_t**)TLS_SLOT(tls_base, MEMTRACE_TLS_OFFS_BUF_PTR)

#define MINSERT instrlist_meta_preinsert

static void memtrace(void* drcontext) {
  per_thread_t* data;
  mem_ref_t *mem_ref, *buf_ptr;

  data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_idx);
  buf_ptr = BUF_PTR(data->seg_base);
  /* Example of dumpped file content:
   *   0x00007f59c2d002d3:  5, call
   *   0x00007ffeacab0ec8:  8, w
   */
  /* We use libc's fprintf as it is buffered and much faster than dr_fprintf
   * for repeated printing that dominates performance, as the printing does here.
   */
  for (mem_ref = (mem_ref_t*)data->buf_base; mem_ref < buf_ptr; mem_ref++) {
    /* We use PIFX to avoid leading zeroes and shrink the resulting file. */
    fprintf(data->logf, "" PIFX ": %2d, %s\n", (ptr_uint_t)mem_ref->addr, mem_ref->size,
            (mem_ref->type > REF_TYPE_WRITE) ? decode_opcode_name(mem_ref->type) /* opcode for instr */
                                             : (mem_ref->type == REF_TYPE_WRITE ? "w" : "r"));

    data->num_refs++;

    data->writer.WriteUint16LE(mem_ref->type);
    data->writer.WriteUint16LE(mem_ref->size);
    data->writer.WriteUint64LE(reinterpret_cast<uint64_t>(reinterpret_cast<uintptr_t>(mem_ref->addr)));
  }
  BUF_PTR(data->seg_base) = data->buf_base;
}

/* clean_call dumps the memory reference info to the log file */
static void clean_call(void) {
  void* drcontext = dr_get_current_drcontext();
  memtrace(drcontext);
}

static void insert_load_buf_ptr(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t reg_ptr) {
  dr_insert_read_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + MEMTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
}

static void insert_update_buf_ptr(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t reg_ptr, int adjust) {
  MINSERT(ilist, where, XINST_CREATE_add(drcontext, opnd_create_reg(reg_ptr), OPND_CREATE_INT16(adjust)));
  dr_insert_write_raw_tls(drcontext, ilist, where, tls_seg, tls_offs + MEMTRACE_TLS_OFFS_BUF_PTR, reg_ptr);
}

static void insert_save_type(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t base, reg_id_t scratch,
                             ushort type) {
  scratch = reg_resize_to_opsz(scratch, OPSZ_2);
  MINSERT(ilist, where, XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch), OPND_CREATE_INT16(type)));
  MINSERT(ilist, where,
          XINST_CREATE_store_2bytes(drcontext, OPND_CREATE_MEM16(base, offsetof(mem_ref_t, type)),
                                    opnd_create_reg(scratch)));
}

static void insert_save_size(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t base, reg_id_t scratch,
                             ushort size) {
  scratch = reg_resize_to_opsz(scratch, OPSZ_2);
  MINSERT(ilist, where, XINST_CREATE_load_int(drcontext, opnd_create_reg(scratch), OPND_CREATE_INT16(size)));
  MINSERT(ilist, where,
          XINST_CREATE_store_2bytes(drcontext, OPND_CREATE_MEM16(base, offsetof(mem_ref_t, size)),
                                    opnd_create_reg(scratch)));
}

static void insert_save_pc(void* drcontext, instrlist_t* ilist, instr_t* where, reg_id_t base, reg_id_t scratch,
                           app_pc pc) {
  instrlist_insert_mov_immed_ptrsz(drcontext, (ptr_int_t)pc, opnd_create_reg(scratch), ilist, where, NULL, NULL);
  MINSERT(ilist, where,
          XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(base, offsetof(mem_ref_t, addr)), opnd_create_reg(scratch)));
}

static void insert_save_addr(void* drcontext, instrlist_t* ilist, instr_t* where, opnd_t ref, reg_id_t reg_ptr,
                             reg_id_t reg_addr) {
  bool ok;
  /* we use reg_ptr as scratch to get addr */
  ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, reg_addr, reg_ptr);
  DR_ASSERT(ok);
  insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);
  MINSERT(
      ilist, where,
      XINST_CREATE_store(drcontext, OPND_CREATE_MEMPTR(reg_ptr, offsetof(mem_ref_t, addr)), opnd_create_reg(reg_addr)));
}

/* insert inline code to add an instruction entry into the buffer */
static void instrument_instr(void* drcontext, instrlist_t* ilist, instr_t* where, instr_t* instr) {
  /* We need two scratch registers */
  reg_id_t reg_ptr, reg_tmp;
  /* we don't want to predicate this, because an instruction fetch always occurs */
  instrlist_set_auto_predicate(ilist, DR_PRED_NONE);
  if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
      drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) != DRREG_SUCCESS) {
    DR_ASSERT(false); /* cannot recover */
    return;
  }
  insert_load_buf_ptr(drcontext, ilist, where, reg_ptr);
  insert_save_type(drcontext, ilist, where, reg_ptr, reg_tmp, (ushort)instr_get_opcode(instr));
  insert_save_size(drcontext, ilist, where, reg_ptr, reg_tmp, (ushort)instr_length(drcontext, instr));
  insert_save_pc(drcontext, ilist, where, reg_ptr, reg_tmp, instr_get_app_pc(instr));
  insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(mem_ref_t));
  /* Restore scratch registers */
  if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
      drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
    DR_ASSERT(false);
  instrlist_set_auto_predicate(ilist, instr_get_predicate(where));
}

/* insert inline code to add a memory reference info entry into the buffer */
static void instrument_mem(void* drcontext, instrlist_t* ilist, instr_t* where, opnd_t ref, bool write) {
  /* We need two scratch registers */
  reg_id_t reg_ptr, reg_tmp;
  if (drreg_reserve_register(drcontext, ilist, where, NULL, &reg_ptr) != DRREG_SUCCESS ||
      drreg_reserve_register(drcontext, ilist, where, NULL, &reg_tmp) != DRREG_SUCCESS) {
    DR_ASSERT(false); /* cannot recover */
    return;
  }
  /* save_addr should be called first as reg_ptr or reg_tmp maybe used in ref */
  insert_save_addr(drcontext, ilist, where, ref, reg_ptr, reg_tmp);
  insert_save_type(drcontext, ilist, where, reg_ptr, reg_tmp, write ? REF_TYPE_WRITE : REF_TYPE_READ);
  insert_save_size(drcontext, ilist, where, reg_ptr, reg_tmp, (ushort)drutil_opnd_mem_size_in_bytes(ref, where));
  insert_update_buf_ptr(drcontext, ilist, where, reg_ptr, sizeof(mem_ref_t));
  /* Restore scratch registers */
  if (drreg_unreserve_register(drcontext, ilist, where, reg_ptr) != DRREG_SUCCESS ||
      drreg_unreserve_register(drcontext, ilist, where, reg_tmp) != DRREG_SUCCESS)
    DR_ASSERT(false);
}

/* For each memory reference app instr, we insert inline code to fill the buffer
 * with an instruction entry and memory reference entries.
 */
static dr_emit_flags_t event_app_instruction(void* drcontext, void* tag, instrlist_t* bb, instr_t* where,
                                             bool for_trace, bool translating, void* user_data) {
  int i;

  /* Insert code to add an entry for each app instruction. */
  /* Use the drmgr_orig_app_instr_* interface to properly handle our own use
   * of drutil_expand_rep_string() and drx_expand_scatter_gather() (as well
   * as another client/library emulating the instruction stream).
   */
  instr_t* instr_fetch = drmgr_orig_app_instr_for_fetch(drcontext);
  if (instr_fetch != NULL && (instr_reads_memory(instr_fetch) || instr_writes_memory(instr_fetch))) {
    DR_ASSERT(instr_is_app(instr_fetch));
    instrument_instr(drcontext, bb, where, instr_fetch);
  }

  /* Insert code to add an entry for each memory reference opnd. */
  instr_t* instr_operands = drmgr_orig_app_instr_for_operands(drcontext);
  if (instr_operands == NULL || (!instr_reads_memory(instr_operands) && !instr_writes_memory(instr_operands)))
    return DR_EMIT_DEFAULT;
  DR_ASSERT(instr_is_app(instr_operands));

  for (i = 0; i < instr_num_srcs(instr_operands); i++) {
    const opnd_t src = instr_get_src(instr_operands, i);
    if (opnd_is_memory_reference(src)) {
      instrument_mem(drcontext, bb, where, src, false);
    }
  }

  for (i = 0; i < instr_num_dsts(instr_operands); i++) {
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
  app::test(drcontext);

  per_thread_t* data = (per_thread_t*)dr_thread_alloc(drcontext, sizeof(per_thread_t));
  DR_ASSERT(data != NULL);
  drmgr_set_tls_field(drcontext, tls_idx, data);

  /* Keep seg_base in a per-thread data structure so we can get the TLS
   * slot and find where the pointer points to in the buffer.
   */
  data->seg_base = (byte*)dr_get_dr_segment_base(tls_seg);
  data->buf_base = (mem_ref_t*)dr_raw_mem_alloc(MEM_BUF_SIZE, DR_MEMPROT_READ | DR_MEMPROT_WRITE, NULL);
  DR_ASSERT(data->seg_base != NULL && data->buf_base != NULL);
  /* put buf_base to TLS as starting buf_ptr */
  BUF_PTR(data->seg_base) = data->buf_base;

  data->num_refs = 0;

  if (log_to_stderr) {
    data->logf = stderr;
  } else {
    /* We're going to dump our data to a per-thread file.
     * On Windows we need an absolute path so we place it in
     * the same directory as our library. We could also pass
     * in a path as a client argument.
     */
    data->log = log_file_open(client_id, drcontext, NULL /* using client lib path */, "memtrace",
                              DR_FILE_CLOSE_ON_FORK | DR_FILE_ALLOW_LARGE);
    data->logf = log_stream_from_file(data->log);
  }
  fprintf(data->logf, "Format: <data address>: <data size>, <(r)ead/(w)rite/opcode>\n");

  file_t file = OpenUniqueFile(drcontext, client_id, Wrap("hello"), false, true);
  BufferedFileWriter::Make(&data->writer, drcontext, file, 64 * 1024 * 1024);
}

static void event_thread_exit(void* drcontext) {
  per_thread_t* data;
  memtrace(drcontext); /* dump any remaining buffer entries */
  data = (per_thread_t*)drmgr_get_tls_field(drcontext, tls_idx);
  dr_mutex_lock(mutex);
  num_refs += data->num_refs;
  dr_mutex_unlock(mutex);
  if (!log_to_stderr) log_stream_close(data->logf); /* closes fd too */
  data->writer.FlushAndDestroy();
  dr_raw_mem_free(data->buf_base, MEM_BUF_SIZE);
  dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static void event_exit(void) {
  dr_log(NULL, DR_LOG_ALL, 1, "Client 'memtrace' num refs seen: " SZFMT "\n", num_refs);
  if (!dr_raw_tls_cfree(tls_offs, MEMTRACE_TLS_COUNT)) DR_ASSERT(false);

  if (!drmgr_unregister_tls_field(tls_idx) || !drmgr_unregister_thread_init_event(event_thread_init) ||
      !drmgr_unregister_thread_exit_event(event_thread_exit) || !drmgr_unregister_bb_app2app_event(event_bb_app2app) ||
      !drmgr_unregister_bb_insertion_event(event_app_instruction) || drreg_exit() != DRREG_SUCCESS)
    DR_ASSERT(false);

  dr_mutex_destroy(mutex);
  drutil_exit();
  drmgr_exit();
  drx_exit();
}

DR_EXPORT void dr_client_main(client_id_t id, int argc, const char* argv[]) {
  /* We need 2 reg slots beyond drreg's eflags slots => 3 slots */
  drreg_options_t ops = {sizeof(ops), 3, false};
  dr_set_client_name("DynamoRIO Sample Client 'memtrace'", "http://dynamorio.org/issues");

  if (argc > 1) {
    if (argc == 2 && strcmp(argv[1], "-log_to_stderr") == 0)
      log_to_stderr = true;
    else {
      dr_fprintf(STDERR, "Error: unknown options: only -log_to_stderr is supported\n");
      dr_abort();
    }
  }

  if (!drmgr_init() || drreg_init(&ops) != DRREG_SUCCESS || !drutil_init() || !drx_init()) DR_ASSERT(false);

  /* register events */
  dr_register_exit_event(event_exit);
  if (!drmgr_register_thread_init_event(event_thread_init) || !drmgr_register_thread_exit_event(event_thread_exit) ||
      !drmgr_register_bb_app2app_event(event_bb_app2app, NULL) ||
      !drmgr_register_bb_instrumentation_event(NULL /*analysis_func*/, event_app_instruction, NULL))
    DR_ASSERT(false);

  client_id = id;
  mutex = dr_mutex_create();

  tls_idx = drmgr_register_tls_field();
  DR_ASSERT(tls_idx != -1);
  /* The TLS field provided by DR cannot be directly accessed from the code cache.
   * For better performance, we allocate raw TLS so that we can directly
   * access and update it with a single instruction.
   */
  if (!dr_raw_tls_calloc(&tls_seg, &tls_offs, MEMTRACE_TLS_COUNT, 0)) DR_ASSERT(false);

  /* make it easy to tell, by looking at log file, which client executed */
  dr_log(NULL, DR_LOG_ALL, 1, "Client 'memtrace' initializing\n");
}
