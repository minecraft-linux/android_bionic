/*
 * Copyright (C) 2019 The Android Open Source Project
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 * OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include "linker_relocate.h"

#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <locale.h>
#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <wchar.h>
#include <wctype.h>
#include <sys/syscall.h>
#include <sys/eventfd.h>
#include <poll.h>
#include <time.h>
#include <unistd.h>

// Futex constants for bionic pthread compatibility stubs
#ifndef FUTEX_WAIT
#define FUTEX_WAIT 0
#endif
#ifndef FUTEX_WAKE
#define FUTEX_WAKE 1
#endif
#ifndef FUTEX_PRIVATE_FLAG
#define FUTEX_PRIVATE_FLAG 128
#endif

#include <type_traits>
#include <unordered_set>

#include "linker.h"
#include "linker_debug.h"
#include "linker_globals.h"
#include "linker_gnu_hash.h"
#include "linker_phdr.h"
#include "linker_relocs.h"
#include "linker_reloc_iterators.h"
#include "linker_sleb128.h"
#include "linker_soinfo.h"
#include "private/bionic_globals.h"

#if defined(__x86_64__)
// No-op stub for unresolved PLT entries (LLD bug workaround).
// Returns 0 in rax, which means "success" for functions returning int
// (e.g., pthread_mutex_lock returns 0 on success).
static int unrelocated_plt_noop(void) {
    return 0;
}

// Bionic-compatible pthread_cond_wait using Linux futex directly.
//
// libPlayFabMultiplayer.so has NO dynamic pthread symbols - all pthread PLT
// entries lack JUMP_SLOT relocations (LLD bug). The statically-linked bionic
// code uses bionic's native futex-based format for all pthread objects.
//
// Bionic's pthread_cond_t layout (LP64):
//   atomic_uint state;       // offset 0, 4 bytes
//   char __reserved[44];     // offset 4
//
// state field:
//   bit 0:   COND_SHARED_MASK  (process-shared flag)
//   bit 1:   COND_CLOCK_MASK   (clock type)
//   bits 2+: counter           (incremented by signal/broadcast)
//
// Wait protocol: load state, unlock mutex, futex_wait on state, relock mutex.
// Signal/broadcast: increment counter by 4 (skipping flag bits), futex_wake.
//
// Note: We call glibc's pthread_mutex_lock/unlock directly, which works with
// bionic-format NORMAL mutexes on x86_64 little-endian because both use
// 0/1/2 (unlocked/locked/contended) in the first 4 bytes at offset 0.
static int bionic_pthread_cond_timedwait(void* cond, void* mutex, const struct timespec* abstime) {
    unsigned int* state_ptr = reinterpret_cast<unsigned int*>(cond);
    unsigned int old_state = __atomic_load_n(state_ptr, __ATOMIC_RELAXED);
    int futex_op = FUTEX_WAIT;
    if (!(old_state & 1))
        futex_op |= FUTEX_PRIVATE_FLAG;

    // Convert absolute time to relative timeout for futex
    struct timespec now, rel;
    clock_gettime(CLOCK_REALTIME, &now);
    rel.tv_sec = abstime->tv_sec - now.tv_sec;
    rel.tv_nsec = abstime->tv_nsec - now.tv_nsec;
    if (rel.tv_nsec < 0) {
        rel.tv_sec--;
        rel.tv_nsec += 1000000000L;
    }
    if (rel.tv_sec < 0) {
        // Already timed out
        return 110; // ETIMEDOUT on Android/bionic
    }

    pthread_mutex_unlock(reinterpret_cast<pthread_mutex_t*>(mutex));
    long ret = syscall(SYS_futex, state_ptr, futex_op, old_state, &rel, nullptr, 0);
    int saved_errno = errno;
    pthread_mutex_lock(reinterpret_cast<pthread_mutex_t*>(mutex));
    if (ret == -1 && saved_errno == ETIMEDOUT)
        return 110; // ETIMEDOUT on Android/bionic
    return 0;
}

static int bionic_pthread_cond_wait(void* cond, void* mutex) {
    unsigned int* state_ptr = reinterpret_cast<unsigned int*>(cond);
    unsigned int old_state = __atomic_load_n(state_ptr, __ATOMIC_RELAXED);

    // Bit 0 clear = process-private, use FUTEX_PRIVATE_FLAG for performance
    int futex_op = FUTEX_WAIT;
    if (!(old_state & 1))
        futex_op |= FUTEX_PRIVATE_FLAG;

    pthread_mutex_unlock(reinterpret_cast<pthread_mutex_t*>(mutex));
    syscall(SYS_futex, state_ptr, futex_op, old_state, nullptr, nullptr, 0);
    pthread_mutex_lock(reinterpret_cast<pthread_mutex_t*>(mutex));

    return 0;
}

// Bionic-compatible pthread_cond_broadcast.
static int bionic_pthread_cond_broadcast(void* cond) {
    unsigned int* state_ptr = reinterpret_cast<unsigned int*>(cond);
    unsigned int old_state = __atomic_load_n(state_ptr, __ATOMIC_RELAXED);

    int futex_op = FUTEX_WAKE;
    if (!(old_state & 1))
        futex_op |= FUTEX_PRIVATE_FLAG;

    // Increment counter by 4 (COND_COUNTER_STEP), skipping the 2 flag bits
    __atomic_fetch_add(state_ptr, 4, __ATOMIC_RELAXED);

    syscall(SYS_futex, state_ptr, futex_op, INT_MAX, nullptr, nullptr, 0);
    return 0;
}

// Bionic-compatible pthread_cond_signal (wake one waiter).
static int bionic_pthread_cond_signal(void* cond) {
    unsigned int* state_ptr = reinterpret_cast<unsigned int*>(cond);
    unsigned int old_state = __atomic_load_n(state_ptr, __ATOMIC_RELAXED);

    int futex_op = FUTEX_WAKE;
    if (!(old_state & 1))
        futex_op |= FUTEX_PRIVATE_FLAG;

    __atomic_fetch_add(state_ptr, 4, __ATOMIC_RELAXED);

    syscall(SYS_futex, state_ptr, futex_op, 1, nullptr, nullptr, 0);
    return 0;
}

// POSIX-compatible strerror_r wrapper.
// Bionic uses POSIX strerror_r (returns 0 on success), but glibc with
// _GNU_SOURCE returns char* instead. This wrapper provides POSIX semantics.
static int posix_strerror_r(int errnum, char* buf, size_t buflen) {
    char* result = strerror_r(errnum, buf, buflen);
    if (result && result != buf && buflen > 0) {
        strncpy(buf, result, buflen);
        buf[buflen - 1] = '\0';
    }
    return 0;
}

// Address of the real __emutls_get_address inside libPlayFabMultiplayer.so.
// Set during PLT fixup so our sanitizing wrapper can call through to it.
static uintptr_t saved_real_emutls = 0;

// Sanitizing wrapper for __emutls_get_address.
// PairIP binary protection encrypts the .data section of libPlayFabMultiplayer.so,
// leaving emutls_control structs with garbage values. When __emutls_get_address
// reads a garbage index field, it computes an absurd realloc size and crashes.
// This wrapper intercepts all calls, detects corrupted controls (index > 100),
// and fixes them before passing to the real function.
static void* sanitize_emutls_get_address(void* control) {
    uint64_t* c = (uint64_t*)control;
    // emutls_control layout: [0]=size [1]=align [2]=index [3]=value
    // Valid index is 0 (uninitialized) or small sequential (1,2,3,...).
    // PairIP-encrypted index is a random 64-bit value >> 100.
    if (c[2] > 100) {
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
            "Sanitizing emutls_control at %p: size=0x%lx align=0x%lx index=0x%lx value=0x%lx",
            control, (unsigned long)c[0], (unsigned long)c[1],
            (unsigned long)c[2], (unsigned long)c[3]);
        c[0] = 1024;  // size (generous default for any TLS variable)
        c[1] = 8;     // align
        c[2] = 0;     // index = 0 (force fresh allocation at runtime)
        c[3] = 0;     // value = NULL (zero-initialize)
    }
    typedef void* (*emutls_fn_t)(void*);
    return ((emutls_fn_t)saved_real_emutls)(control);
}

// Debug wrappers for tracing __emutls_get_address behavior.
// These log all calls from libPlayFabMultiplayer.so (via PLT redirection)
// to help diagnose the SIGABRT in __emutls_get_address.
static int debug_log_count = 0;
static const int DEBUG_LOG_MAX = 200;

static void* debug_malloc(size_t size) {
    void* result = malloc(size);
    int n = __atomic_fetch_add(&debug_log_count, 1, __ATOMIC_RELAXED);
    if (n < DEBUG_LOG_MAX) {
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
            "PLT malloc(%zu) = %p", size, result);
    }
    return result;
}

static void* debug_realloc(void* ptr, size_t size) {
    int n = __atomic_fetch_add(&debug_log_count, 1, __ATOMIC_RELAXED);
    if (size > 0x40000000UL) {
        // Suspicious huge realloc - likely corrupted emutls_control index.
        // In __emutls_get_address, rbx holds the emutls_control pointer.
        // Capture it to identify which control struct needs patching.
        // NOTE: Do NOT use __builtin_return_address(1) - it segfaults
        // when frame pointers are omitted (default on x86_64).
        void* rbx_val;
        __asm__ volatile ("mov %%rbx, %0" : "=r"(rbx_val));
        void* caller = __builtin_return_address(0);
        async_safe_format_log(ANDROID_LOG_ERROR, "linker",
            "PLT realloc(%p, %zu) HUGE SIZE! caller=%p rbx=%p",
            ptr, size, caller, rbx_val);
        // Dump the emutls_control struct pointed to by rbx
        uint64_t* control = (uint64_t*)rbx_val;
        async_safe_format_log(ANDROID_LOG_ERROR, "linker",
            "emutls_control dump: size=0x%lx align=0x%lx index=0x%lx value=0x%lx",
            (unsigned long)control[0], (unsigned long)control[1],
            (unsigned long)control[2], (unsigned long)control[3]);
        abort();
    }
    if (n < DEBUG_LOG_MAX) {
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
            "PLT realloc(%p, %zu) ...", ptr, size);
    }
    void* result = realloc(ptr, size);
    if (n < DEBUG_LOG_MAX) {
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
            "PLT realloc(%p, %zu) = %p (errno=%d)", ptr, size, result, errno);
    }
    return result;
}

static int debug_pthread_key_create(pthread_key_t* key, void (*destructor)(void*)) {
    int result = pthread_key_create(key, destructor);
    int n = __atomic_fetch_add(&debug_log_count, 1, __ATOMIC_RELAXED);
    if (n < DEBUG_LOG_MAX) {
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
            "PLT pthread_key_create() = %d, key=%u", result, (unsigned)*key);
    }
    return result;
}

static void* debug_pthread_getspecific(pthread_key_t key) {
    void* result = pthread_getspecific(key);
    int n = __atomic_fetch_add(&debug_log_count, 1, __ATOMIC_RELAXED);
    if (n < DEBUG_LOG_MAX) {
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
            "PLT pthread_getspecific(%u) = %p", (unsigned)key, result);
    }
    return result;
}

static int debug_pthread_setspecific(pthread_key_t key, const void* value) {
    int result = pthread_setspecific(key, value);
    int n = __atomic_fetch_add(&debug_log_count, 1, __ATOMIC_RELAXED);
    if (n < DEBUG_LOG_MAX) {
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
            "PLT pthread_setspecific(%u, %p) = %d", (unsigned)key, value, result);
    }
    return result;
}

static int debug_pthread_once(pthread_once_t* once_control, void (*init_routine)(void)) {
    int n = __atomic_fetch_add(&debug_log_count, 1, __ATOMIC_RELAXED);
    if (n < DEBUG_LOG_MAX) {
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
            "PLT pthread_once(%p [val=%d], %p)", once_control, *(int*)once_control, (void*)init_routine);
    }
    int result = pthread_once(once_control, init_routine);
    if (n < DEBUG_LOG_MAX) {
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
            "PLT pthread_once done = %d [val=%d]", result, *(int*)once_control);
    }
    return result;
}

// PLT resolver for handling unrelocated .got.plt entries.
// When an unrelocated PLT entry is called, the PLT fallback code pushes
// the PLT index and jumps through GOT[2] to this resolver.
//
// Stack on entry: [GOT[1]] [PLT_index] [return_addr]
//
// The resolver looks up the symbol via .rela.plt (by r_offset) and resolves it.
// If no .rela.plt entry exists, it aborts with diagnostic info.

extern "C" ElfW(Addr) plt_resolve_handler(void* got1_soinfo, long plt_index, void* return_addr);

__attribute__((naked)) static void plt_resolver_trampoline() {
    asm volatile(
        // Save caller-saved registers
        "sub $0x38, %%rsp\n"
        "mov %%rax, 0x00(%%rsp)\n"
        "mov %%rcx, 0x08(%%rsp)\n"
        "mov %%rdx, 0x10(%%rsp)\n"
        "mov %%rsi, 0x18(%%rsp)\n"
        "mov %%rdi, 0x20(%%rsp)\n"
        "mov %%r8,  0x28(%%rsp)\n"
        "mov %%r9,  0x30(%%rsp)\n"
        // Extract GOT[1] (soinfo*), PLT index, and return address from stack
        "mov 0x38(%%rsp), %%rdi\n"  // GOT[1] = soinfo*
        "mov 0x40(%%rsp), %%rsi\n"  // PLT index
        "mov 0x48(%%rsp), %%rdx\n"  // caller return address
        "call plt_resolve_handler\n"
        "mov %%rax, %%r11\n"        // Save resolved address
        // Restore caller-saved registers
        "mov 0x00(%%rsp), %%rax\n"
        "mov 0x08(%%rsp), %%rcx\n"
        "mov 0x10(%%rsp), %%rdx\n"
        "mov 0x18(%%rsp), %%rsi\n"
        "mov 0x20(%%rsp), %%rdi\n"
        "mov 0x28(%%rsp), %%r8\n"
        "mov 0x30(%%rsp), %%r9\n"
        // Pop save area (0x38) + GOT[1] (0x08) + PLT index (0x08)
        "add $0x48, %%rsp\n"
        // Jump to resolved function (return addr is now on top of stack)
        "jmp *%%r11\n"
        ::: "memory"
    );
}

extern "C" ElfW(Addr) plt_resolve_handler(void* got1_soinfo, long plt_index, void* return_addr) {
    soinfo* si = reinterpret_cast<soinfo*>(got1_soinfo);
    if (!si) {
        fprintf(stderr, "FATAL: PLT resolver called with null soinfo (index=%ld)\n", plt_index);
        abort();
    }

    // Compute the .got.plt entry address for this PLT index
    ElfW(Addr)* got_entry = si->plt_got_addr_ + plt_index + 3;
    ElfW(Addr) got_entry_addr = reinterpret_cast<ElfW(Addr)>(got_entry);

    // Search .rela.plt for an entry with matching r_offset
#if defined(USE_RELA)
    if (si->plt_rela_ != nullptr) {
        for (size_t i = 0; i < si->plt_rela_count_; i++) {
            ElfW(Addr) r_offset_addr = si->load_bias + si->plt_rela_[i].r_offset;
            if (r_offset_addr == got_entry_addr) {
                // Found the relocation! Resolve the symbol.
                uint32_t sym_idx = ELF64_R_SYM(si->plt_rela_[i].r_info);
                const char* sym_name = si->strtab_ + si->symtab_[sym_idx].st_name;
                INFO("[ PLT resolver: index=%ld -> symbol '%s' ]", plt_index, sym_name);

                // Try to find the symbol in loaded libraries
                const ElfW(Sym)* found_sym = nullptr;
                const soinfo* found_si = nullptr;

                // Use the soinfo's lookup functionality
                // First check if it's defined in this library
                ElfW(Sym)* local_sym = &si->symtab_[sym_idx];
                if (local_sym->st_shndx != SHN_UNDEF) {
                    ElfW(Addr) resolved = si->load_bias + local_sym->st_value;
                    *got_entry = resolved;
                    return resolved;
                }

                // Symbol is undefined - would need to search other libraries
                // For now, abort with diagnostic info
                fprintf(stderr, "FATAL: PLT resolver cannot resolve undefined symbol '%s' (index=%ld)\n",
                        sym_name, plt_index);
                abort();
            }
        }
    }
#endif

    // No .rela.plt entry found for this .got.plt address.
    // This is an unrelocated entry caused by an LLD bug where JUMP_SLOT
    // relocations are missing for some PLT entries. The symbol name cannot
    // be determined. Provide a no-op stub that returns 0.
    ElfW(Addr) caller_offset = reinterpret_cast<ElfW(Addr)>(return_addr) - si->load_bias;
    fprintf(stderr, "WARNING: unresolved PLT entry %ld in %s (caller offset 0x%lx) - using no-op stub\n",
            plt_index, si->get_realpath(), (unsigned long)caller_offset);

    ElfW(Addr) noop_addr = reinterpret_cast<ElfW(Addr)>(unrelocated_plt_noop);
    *got_entry = noop_addr;
    return noop_addr;
}
#endif // __x86_64__

static bool is_tls_reloc(ElfW(Word) type) {
  switch (type) {
    case R_GENERIC_TLS_DTPMOD:
    case R_GENERIC_TLS_DTPREL:
    case R_GENERIC_TLS_TPREL:
    case R_GENERIC_TLSDESC:
      return true;
    default:
      return false;
  }
}

class Relocator {
 public:
  Relocator(const VersionTracker& version_tracker, const SymbolLookupList& lookup_list)
      : version_tracker(version_tracker), lookup_list(lookup_list)
  {}

  soinfo* si = nullptr;
  const char* si_strtab = nullptr;
  size_t si_strtab_size = 0;
  ElfW(Sym)* si_symtab = nullptr;

  const VersionTracker& version_tracker;
  const SymbolLookupList& lookup_list;

  // Cache key
  ElfW(Word) cache_sym_val = 0;
  // Cache value
  const ElfW(Sym)* cache_sym = nullptr;
  soinfo* cache_si = nullptr;

  std::vector<TlsDynamicResolverArg>* tlsdesc_args;
  std::vector<std::pair<TlsDescriptor*, size_t>> deferred_tlsdesc_relocs;
  size_t tls_tp_base = 0;

  __attribute__((always_inline))
  const char* get_string(ElfW(Word) index) {
    if (__predict_false(index >= si_strtab_size)) {
      async_safe_fatal("%s: strtab out of bounds error; STRSZ=%zd, name=%d",
                       si->get_realpath(), si_strtab_size, index);
    }
    return si_strtab + index;
  }
};

template <bool DoLogging>
__attribute__((always_inline))
static inline bool lookup_symbol(Relocator& relocator, uint32_t r_sym, const char* sym_name,
                                 soinfo** found_in, const ElfW(Sym)** sym) {
  if (r_sym == relocator.cache_sym_val) {
    *found_in = relocator.cache_si;
    *sym = relocator.cache_sym;
    count_relocation_if<DoLogging>(kRelocSymbolCached);
  } else {
    const version_info* vi = nullptr;
    if (!relocator.si->lookup_version_info(relocator.version_tracker, r_sym, sym_name, &vi)) {
      return false;
    }

    soinfo* local_found_in = nullptr;
    const ElfW(Sym)* local_sym = soinfo_do_lookup(sym_name, vi, &local_found_in, relocator.lookup_list);

    relocator.cache_sym_val = r_sym;
    relocator.cache_si = local_found_in;
    relocator.cache_sym = local_sym;
    *found_in = local_found_in;
    *sym = local_sym;
  }

  if (*sym == nullptr) {
    if (ELF_ST_BIND(relocator.si_symtab[r_sym].st_info) != STB_WEAK) {
      if(!relocator.si->is_linked()) {
        DL_ERR("cannot locate symbol \"%s\" referenced by \"%s\"...", sym_name, relocator.si->get_realpath());
        return false;
      }
    }
  }

  count_relocation_if<DoLogging>(kRelocSymbol);
  return true;
}

enum class RelocMode {
  // Fast path for JUMP_SLOT relocations.
  JumpTable,
  // Fast path for typical relocations: ABSOLUTE, GLOB_DAT, or RELATIVE.
  Typical,
  // Handle all relocation types, relocations in text sections, and statistics/tracing.
  General,
};

struct linker_stats_t {
  int count[kRelocMax];
};

static linker_stats_t linker_stats;

void count_relocation(RelocationKind kind) {
  ++linker_stats.count[kind];
}

void print_linker_stats() {
  PRINT("RELO STATS: %s: %d abs, %d rel, %d symbol (%d cached)",
         g_argv[0],
         linker_stats.count[kRelocAbsolute],
         linker_stats.count[kRelocRelative],
         linker_stats.count[kRelocSymbol],
         linker_stats.count[kRelocSymbolCached]);
}

static bool process_relocation_general(Relocator& relocator, const rel_t& reloc);

template <RelocMode Mode>
__attribute__((always_inline))
static bool process_relocation_impl(Relocator& relocator, const rel_t& reloc) {
  constexpr bool IsGeneral = Mode == RelocMode::General;

  void* const rel_target = reinterpret_cast<void*>(reloc.r_offset + relocator.si->load_bias);
  const uint32_t r_type = ELFW(R_TYPE)(reloc.r_info);
  const uint32_t r_sym = ELFW(R_SYM)(reloc.r_info);

  soinfo* found_in = nullptr;
  const ElfW(Sym)* sym = nullptr;
  const char* sym_name = nullptr;
  ElfW(Addr) sym_addr = 0;

  if (r_sym != 0) {
    sym_name = relocator.get_string(relocator.si_symtab[r_sym].st_name);
  }

  // While relocating a DSO with text relocations (obsolete and 32-bit only), the .text segment is
  // writable (but not executable). To call an ifunc, temporarily remap the segment as executable
  // (but not writable). Then switch it back to continue applying relocations in the segment.
#if defined(__LP64__)
  const bool handle_text_relocs = false;
  auto protect_segments = []() { return true; };
  auto unprotect_segments = []() { return true; };
#else
  const bool handle_text_relocs = IsGeneral && relocator.si->has_text_relocations;
  auto protect_segments = [&]() {
    // Make .text executable.
    if (phdr_table_protect_segments(relocator.si->phdr, relocator.si->phnum,
                                    relocator.si->load_bias) < 0) {
      DL_ERR("can't protect segments for \"%s\": %s",
             relocator.si->get_realpath(), strerror(errno));
      return false;
    }
    return true;
  };
  auto unprotect_segments = [&]() {
    // Make .text writable.
    if (phdr_table_unprotect_segments(relocator.si->phdr, relocator.si->phnum,
                                      relocator.si->load_bias) < 0) {
      DL_ERR("can't unprotect loadable segments for \"%s\": %s",
             relocator.si->get_realpath(), strerror(errno));
      return false;
    }
    return true;
  };
#endif

  auto trace_reloc = [](const char* fmt, ...) __printflike(2, 3) {
    if (IsGeneral &&
        g_ld_debug_verbosity > LINKER_VERBOSITY_TRACE &&
        DO_TRACE_RELO) {
      va_list ap;
      va_start(ap, fmt);
      linker_log_va_list(LINKER_VERBOSITY_TRACE, fmt, ap);
      va_end(ap);
    }
  };

  // Skip symbol lookup for R_GENERIC_NONE relocations.
  if (__predict_false(r_type == R_GENERIC_NONE)) {
    trace_reloc("RELO NONE");
    return true;
  }

#if defined(USE_RELA)
  auto get_addend_rel   = [&]() -> ElfW(Addr) { return reloc.r_addend; };
  auto get_addend_norel = [&]() -> ElfW(Addr) { return reloc.r_addend; };
#else
  auto get_addend_rel   = [&]() -> ElfW(Addr) { return *static_cast<ElfW(Addr)*>(rel_target); };
  auto get_addend_norel = [&]() -> ElfW(Addr) { return 0; };
#endif

  if (IsGeneral && is_tls_reloc(r_type)) {
    if (r_sym == 0) {
      // By convention in ld.bfd and lld, an omitted symbol on a TLS relocation
      // is a reference to the current module.
      found_in = relocator.si;
    } else if (ELF_ST_BIND(relocator.si_symtab[r_sym].st_info) == STB_LOCAL) {
      // In certain situations, the Gold linker accesses a TLS symbol using a
      // relocation to an STB_LOCAL symbol in .dynsym of either STT_SECTION or
      // STT_TLS type. Bionic doesn't support these relocations, so issue an
      // error. References:
      //  - https://groups.google.com/d/topic/generic-abi/dJ4_Y78aQ2M/discussion
      //  - https://sourceware.org/bugzilla/show_bug.cgi?id=17699
      sym = &relocator.si_symtab[r_sym];
      DL_ERR("unexpected TLS reference to local symbol \"%s\" in \"%s\": sym type %d, rel type %u",
             sym_name, relocator.si->get_realpath(), ELF_ST_TYPE(sym->st_info), r_type);
      return false;
    } else if (!lookup_symbol<IsGeneral>(relocator, r_sym, sym_name, &found_in, &sym)) {
      return false;
    }
    if (found_in != nullptr && found_in->get_tls() == nullptr) {
      // sym_name can be nullptr if r_sym is 0. A linker should never output an ELF file like this.
      DL_ERR("TLS relocation refers to symbol \"%s\" in solib \"%s\" with no TLS segment",
             sym_name, found_in->get_realpath());
      return false;
    }
    if (sym != nullptr) {
      if (ELF_ST_TYPE(sym->st_info) != STT_TLS) {
        // A toolchain should never output a relocation like this.
        DL_ERR("reference to non-TLS symbol \"%s\" from TLS relocation in \"%s\"",
               sym_name, relocator.si->get_realpath());
        return false;
      }
      sym_addr = sym->st_value;
    }
  } else {
    if (r_sym == 0) {
      // Do nothing.
    } else {
      if (!lookup_symbol<IsGeneral>(relocator, r_sym, sym_name, &found_in, &sym)) return false;
      if (sym != nullptr) {
        const bool should_protect_segments = handle_text_relocs &&
                                             found_in == relocator.si &&
                                             ELF_ST_TYPE(sym->st_info) == STT_GNU_IFUNC;
        if (should_protect_segments && !protect_segments()) return false;
        sym_addr = found_in->resolve_symbol_address(sym);
        if (should_protect_segments && !unprotect_segments()) return false;
      } else if constexpr (IsGeneral) {
        if(!relocator.si->is_linked()) {
          // A weak reference to an undefined symbol. We typically use a zero symbol address, but
          // use the relocation base for PC-relative relocations, so that the value written is zero.
          switch (r_type) {
  #if defined(__x86_64__)
            case R_X86_64_PC32:
              sym_addr = reinterpret_cast<ElfW(Addr)>(rel_target);
              break;
  #elif defined(__i386__)
            case R_386_PC32:
              sym_addr = reinterpret_cast<ElfW(Addr)>(rel_target);
              break;
  #endif
          }
        }
      }
    }
  }
  if(relocator.si->is_linked()) {
    if(sym_addr == 0) {
      return true;
    }
  }

  if constexpr (IsGeneral || Mode == RelocMode::JumpTable) {
    if (r_type == R_GENERIC_JUMP_SLOT) {
      count_relocation_if<IsGeneral>(kRelocAbsolute);
      const ElfW(Addr) result = sym_addr + get_addend_norel();
      trace_reloc("RELO JMP_SLOT %16p <- %16p %s",
                  rel_target, reinterpret_cast<void*>(result), sym_name);
      *static_cast<ElfW(Addr)*>(rel_target) = result;
      return true;
    }
  }

  if constexpr (IsGeneral || Mode == RelocMode::Typical) {
    // Almost all dynamic relocations are of one of these types, and most will be
    // R_GENERIC_ABSOLUTE. The platform typically uses RELR instead, but R_GENERIC_RELATIVE is
    // common in non-platform binaries.
    if (r_type == R_GENERIC_ABSOLUTE) {
      count_relocation_if<IsGeneral>(kRelocAbsolute);
      const ElfW(Addr) result = sym_addr + get_addend_rel();
      trace_reloc("RELO ABSOLUTE %16p <- %16p %s",
                  rel_target, reinterpret_cast<void*>(result), sym_name);
      *static_cast<ElfW(Addr)*>(rel_target) = result;
      return true;
    } else if (r_type == R_GENERIC_GLOB_DAT) {
      // The i386 psABI specifies that R_386_GLOB_DAT doesn't have an addend. The ARM ELF ABI
      // document (IHI0044F) specifies that R_ARM_GLOB_DAT has an addend, but Bionic isn't adding
      // it.
      count_relocation_if<IsGeneral>(kRelocAbsolute);
      const ElfW(Addr) result = sym_addr + get_addend_norel();
      trace_reloc("RELO GLOB_DAT %16p <- %16p %s",
                  rel_target, reinterpret_cast<void*>(result), sym_name);
      *static_cast<ElfW(Addr)*>(rel_target) = result;
      return true;
    } else if (r_type == R_GENERIC_RELATIVE) {
      // In practice, r_sym is always zero, but if it weren't, the linker would still look up the
      // referenced symbol (and abort if the symbol isn't found), even though it isn't used.
      count_relocation_if<IsGeneral>(kRelocRelative);
      const ElfW(Addr) result = relocator.si->load_bias + get_addend_rel();
      trace_reloc("RELO RELATIVE %16p <- %16p",
                  rel_target, reinterpret_cast<void*>(result));
      *static_cast<ElfW(Addr)*>(rel_target) = result;
      return true;
    }
  }

  if constexpr (!IsGeneral) {
    // Almost all relocations are handled above. Handle the remaining relocations below, in a
    // separate function call. The symbol lookup will be repeated, but the result should be served
    // from the 1-symbol lookup cache.
    return process_relocation_general(relocator, reloc);
  }

  switch (r_type) {
    case R_GENERIC_IRELATIVE:
      // In the linker, ifuncs are called as soon as possible so that string functions work. We must
      // not call them again. (e.g. On arm32, resolving an ifunc changes the meaning of the addend
      // from a resolver function to the implementation.)
      if (!relocator.si->is_linker()) {
        count_relocation_if<IsGeneral>(kRelocRelative);
        const ElfW(Addr) ifunc_addr = relocator.si->load_bias + get_addend_rel();
        trace_reloc("RELO IRELATIVE %16p <- %16p",
                    rel_target, reinterpret_cast<void*>(ifunc_addr));
        if (handle_text_relocs && !protect_segments()) return false;
        const ElfW(Addr) result = call_ifunc_resolver(ifunc_addr);
        if (handle_text_relocs && !unprotect_segments()) return false;
        *static_cast<ElfW(Addr)*>(rel_target) = result;
      }
      break;
    case R_GENERIC_COPY:
      // Copy relocations allow read-only data or code in a non-PIE executable to access a
      // variable from a DSO. The executable reserves extra space in its .bss section, and the
      // linker copies the variable into the extra space. The executable then exports its copy
      // to interpose the copy in the DSO.
      //
      // Bionic only supports PIE executables, so copy relocations aren't supported. The ARM and
      // AArch64 ABI documents only allow them for ET_EXEC (non-PIE) objects. See IHI0056B and
      // IHI0044F.
      DL_ERR("%s COPY relocations are not supported", relocator.si->get_realpath());
      return false;
#if 0
    case R_GENERIC_TLS_TPREL:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        ElfW(Addr) tpoff = 0;
        if (found_in == nullptr) {
          // Unresolved weak relocation. Leave tpoff at 0 to resolve
          // &weak_tls_symbol to __get_tls().
        } else {
          CHECK(found_in->get_tls() != nullptr); // We rejected a missing TLS segment above.
          const TlsModule& mod = get_tls_module(found_in->get_tls()->module_id);
          if (mod.static_offset != SIZE_MAX) {
            tpoff += mod.static_offset - relocator.tls_tp_base;
          } else {
            DL_ERR("TLS symbol \"%s\" in dlopened \"%s\" referenced from \"%s\" using IE access model",
                   sym_name, found_in->get_realpath(), relocator.si->get_realpath());
            return false;
          }
        }
        tpoff += sym_addr + get_addend_rel();
        trace_reloc("RELO TLS_TPREL %16p <- %16p %s",
                    rel_target, reinterpret_cast<void*>(tpoff), sym_name);
        *static_cast<ElfW(Addr)*>(rel_target) = tpoff;
      }
      break;
    case R_GENERIC_TLS_DTPMOD:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        size_t module_id = 0;
        if (found_in == nullptr) {
          // Unresolved weak relocation. Evaluate the module ID to 0.
        } else {
          CHECK(found_in->get_tls() != nullptr); // We rejected a missing TLS segment above.
          module_id = found_in->get_tls()->module_id;
        }
        trace_reloc("RELO TLS_DTPMOD %16p <- %zu %s",
                    rel_target, module_id, sym_name);
        *static_cast<ElfW(Addr)*>(rel_target) = module_id;
      }
      break;
    case R_GENERIC_TLS_DTPREL:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        const ElfW(Addr) result = sym_addr + get_addend_rel();
        trace_reloc("RELO TLS_DTPREL %16p <- %16p %s",
                    rel_target, reinterpret_cast<void*>(result), sym_name);
        *static_cast<ElfW(Addr)*>(rel_target) = result;
      }
      break;
#endif

#if defined(__aarch64__)
    // Bionic currently only implements TLSDESC for arm64. This implementation should work with
    // other architectures, as long as the resolver functions are implemented.
    case R_GENERIC_TLSDESC:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        abort();
// Not implemented yet aarch64
#if 0
        ElfW(Addr) addend = reloc.r_addend;
        TlsDescriptor* desc = static_cast<TlsDescriptor*>(rel_target);
        if (found_in == nullptr) {
          // Unresolved weak relocation.
          desc->func = tlsdesc_resolver_unresolved_weak;
          desc->arg = addend;
          trace_reloc("RELO TLSDESC %16p <- unresolved weak, addend 0x%zx %s",
                      rel_target, static_cast<size_t>(addend), sym_name);
        } else {
          CHECK(found_in->get_tls() != nullptr); // We rejected a missing TLS segment above.
          size_t module_id = found_in->get_tls()->module_id;
          const TlsModule& mod = get_tls_module(module_id);
          if (mod.static_offset != SIZE_MAX) {
            desc->func = tlsdesc_resolver_static;
            desc->arg = mod.static_offset - relocator.tls_tp_base + sym_addr + addend;
            trace_reloc("RELO TLSDESC %16p <- static (0x%zx - 0x%zx + 0x%zx + 0x%zx) %s",
                        rel_target, mod.static_offset, relocator.tls_tp_base,
                        static_cast<size_t>(sym_addr), static_cast<size_t>(addend),
                        sym_name);
          } else {
            relocator.tlsdesc_args->push_back({
              .generation = mod.first_generation,
              .index.module_id = module_id,
              .index.offset = sym_addr + addend,
            });
            // Defer the TLSDESC relocation until the address of the TlsDynamicResolverArg object
            // is finalized.
            relocator.deferred_tlsdesc_relocs.push_back({
              desc, relocator.tlsdesc_args->size() - 1
            });
            const TlsDynamicResolverArg& desc_arg = relocator.tlsdesc_args->back();
            trace_reloc("RELO TLSDESC %16p <- dynamic (gen %zu, mod %zu, off %zu) %s",
                        rel_target, desc_arg.generation, desc_arg.index.module_id,
                        desc_arg.index.offset, sym_name);
          }
        }
#endif
      }
      break;
#endif  // defined(__aarch64__)

#if defined(__x86_64__)
    case R_X86_64_32:
      count_relocation_if<IsGeneral>(kRelocAbsolute);
      {
        const Elf32_Addr result = sym_addr + reloc.r_addend;
        trace_reloc("RELO R_X86_64_32 %16p <- 0x%08x %s",
                    rel_target, result, sym_name);
        *static_cast<Elf32_Addr*>(rel_target) = result;
      }
      break;
    case R_X86_64_PC32:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        const ElfW(Addr) target = sym_addr + reloc.r_addend;
        const ElfW(Addr) base = reinterpret_cast<ElfW(Addr)>(rel_target);
        const Elf32_Addr result = target - base;
        trace_reloc("RELO R_X86_64_PC32 %16p <- 0x%08x (%16p - %16p) %s",
                    rel_target, result, reinterpret_cast<void*>(target),
                    reinterpret_cast<void*>(base), sym_name);
        *static_cast<Elf32_Addr*>(rel_target) = result;
      }
      break;
#elif defined(__i386__)
    case R_386_PC32:
      count_relocation_if<IsGeneral>(kRelocRelative);
      {
        const ElfW(Addr) target = sym_addr + get_addend_rel();
        const ElfW(Addr) base = reinterpret_cast<ElfW(Addr)>(rel_target);
        const ElfW(Addr) result = target - base;
        trace_reloc("RELO R_386_PC32 %16p <- 0x%08x (%16p - %16p) %s",
                    rel_target, result, reinterpret_cast<void*>(target),
                    reinterpret_cast<void*>(base), sym_name);
        *static_cast<ElfW(Addr)*>(rel_target) = result;
      }
      break;
#endif
    default:
      DL_ERR("unknown reloc type %d in \"%s\"", r_type, relocator.si->get_realpath());
      return false;
  }
  return true;
}

__attribute__((noinline))
static bool process_relocation_general(Relocator& relocator, const rel_t& reloc) {
  return process_relocation_impl<RelocMode::General>(relocator, reloc);
}

template <RelocMode Mode>
__attribute__((always_inline))
static inline bool process_relocation(Relocator& relocator, const rel_t& reloc) {
  return Mode == RelocMode::General ?
      process_relocation_general(relocator, reloc) :
      process_relocation_impl<Mode>(relocator, reloc);
}

template <RelocMode Mode>
__attribute__((noinline))
static bool plain_relocate_impl(Relocator& relocator, rel_t* rels, size_t rel_count) {
  for (size_t i = 0; i < rel_count; ++i) {
    if (!process_relocation<Mode>(relocator, rels[i])) {
      return false;
    }
  }
  return true;
}

template <RelocMode Mode>
__attribute__((noinline))
static bool packed_relocate_impl(Relocator& relocator, sleb128_decoder decoder) {
  return for_all_packed_relocs(decoder, [&](const rel_t& reloc) {
    return process_relocation<Mode>(relocator, reloc);
  });
}

static bool needs_slow_relocate_loop(const Relocator& relocator __unused) {
#if STATS
  // TODO: This could become a run-time flag.
  return true;
#endif
#if !defined(__LP64__)
  if (relocator.si->has_text_relocations) return true;
#endif
  if (g_ld_debug_verbosity > LINKER_VERBOSITY_TRACE) {
    // If linker TRACE() is enabled, then each relocation is logged.
    return true;
  }
  return false;
}

template <RelocMode OptMode, typename ...Args>
static bool plain_relocate(Relocator& relocator, Args ...args) {
  return needs_slow_relocate_loop(relocator) ?
      plain_relocate_impl<RelocMode::General>(relocator, args...) :
      plain_relocate_impl<OptMode>(relocator, args...);
}

template <RelocMode OptMode, typename ...Args>
static bool packed_relocate(Relocator& relocator, Args ...args) {
  return needs_slow_relocate_loop(relocator) ?
      packed_relocate_impl<RelocMode::General>(relocator, args...) :
      packed_relocate_impl<OptMode>(relocator, args...);
}

bool soinfo::relocate(const SymbolLookupList& lookup_list) {

  VersionTracker version_tracker;

  if (!version_tracker.init(this)) {
    return false;
  }

  Relocator relocator(version_tracker, lookup_list);
  relocator.si = this;
  relocator.si_strtab = strtab_;
  relocator.si_strtab_size = has_min_version(1) ? strtab_size_ : SIZE_MAX;
  relocator.si_symtab = symtab_;
#if 0
  relocator.tlsdesc_args = &tlsdesc_args_;
  relocator.tls_tp_base = __libc_shared_globals()->static_tls_layout.offset_thread_pointer();
#endif

  if (android_relocs_ != nullptr) {
    // check signature
    if (android_relocs_size_ > 3 &&
        android_relocs_[0] == 'A' &&
        android_relocs_[1] == 'P' &&
        android_relocs_[2] == 'S' &&
        android_relocs_[3] == '2') {
      DEBUG("[ android relocating %s ]", get_realpath());

      const uint8_t* packed_relocs = android_relocs_ + 4;
      const size_t packed_relocs_size = android_relocs_size_ - 4;

      if (!packed_relocate<RelocMode::Typical>(relocator, sleb128_decoder(packed_relocs, packed_relocs_size))) {
        return false;
      }
    } else {
      DL_ERR("bad android relocation header.");
      return false;
    }
  }

  if (relr_ != nullptr) {
    DEBUG("[ relocating %s relr ]", get_realpath());
    if (!relocate_relr()) {
      return false;
    }
  }

#if defined(USE_RELA)
  if (rela_ != nullptr) {
    DEBUG("[ relocating %s rela ]", get_realpath());

    if (!plain_relocate<RelocMode::Typical>(relocator, rela_, rela_count_)) {
      return false;
    }
  }
  if (plt_rela_ != nullptr) {
    DEBUG("[ relocating %s plt rela ]", get_realpath());
    if (!plain_relocate<RelocMode::JumpTable>(relocator, plt_rela_, plt_rela_count_)) {
      return false;
    }
  }

#if defined(__x86_64__)
  // Workaround for LLD bug: some .got.plt entries may lack .rela.plt relocations.
  // These entries still contain raw file-level PLT fallback addresses that need
  // load_bias adjustment. We fix them up and set up GOT[2] for lazy resolution.
  if (plt_got_addr_ != nullptr && plt_rela_ != nullptr && plt_rela_count_ > 0) {
    // Build set of .got.plt addresses that were resolved by .rela.plt
    std::unordered_set<ElfW(Addr)> resolved_addrs;
    for (size_t i = 0; i < plt_rela_count_; i++) {
      resolved_addrs.insert(load_bias + plt_rela_[i].r_offset);
    }

    // Known function mappings for unrelocated PLT entries (LLD bug workaround).
    // These are NDK libc/libpthread functions statically linked by LLD without
    // proper JUMP_SLOT relocations. Identified by disassembling callers in
    // libPlayFabMultiplayer.so (__emutls_get_address, std::mutex, std::condition_variable, etc).
    //
    // For simple libc functions (malloc, realloc, memcpy, etc.) we use glibc
    // directly. For pthread mutex functions, glibc's implementations happen to
    // be layout-compatible with bionic's NORMAL mutexes on x86_64 LE (both use
    // 0/1/2 for unlocked/locked/contended in the first 4 bytes). For pthread
    // condvar functions, we use bionic-compatible stubs that implement the
    // correct futex-based protocol (bionic and glibc condvar layouts differ).
    //
    // For FILE* functions (fopen, fprintf, fputc, etc.), bionic::FILE structs
    // are NOT compatible with glibc FILE structs. The libc-shim wraps glibc
    // FILE* in a bionic::FILE struct with the real FILE* at offset 24 (LP64).
    // We must unwrap before calling glibc functions.
    //
    // PLT entries not listed here fall through to the PLT resolver trampoline,
    // which uses a no-op stub (return 0) for unresolvable entries.

    // Bionic FILE* wrappers: unwrap bionic::FILE (glibc FILE* at offset 24)
    // to call glibc functions. fopen wraps the result in a new bionic::FILE.
    struct bionic_file_wrapper {
      static FILE* unwrap(void* bf) {
        return bf ? *reinterpret_cast<FILE**>(reinterpret_cast<char*>(bf) + 24) : nullptr;
      }
      static void* wrap(FILE* f) {
        if (!f) return nullptr;
        char* bf = (char*)calloc(1, 152);
        *reinterpret_cast<const char**>(bf) = "plt_wrap";  // _p
        *reinterpret_cast<FILE**>(bf + 24) = f;            // wrapped
        *reinterpret_cast<int*>(bf + 20) = fileno(f);      // _file
        return bf;
      }
      static void* do_fopen(const char* path, const char* mode) {
        return wrap(::fopen(path, mode));
      }
      static int do_fclose(void* bf) {
        if (!bf) return EOF;
        int ret = ::fclose(unwrap(bf));
        ::free(bf);
        return ret;
      }
      static int do_fprintf(void* bf, const char* fmt, ...) {
        va_list ap;
        va_start(ap, fmt);
        int ret = ::vfprintf(unwrap(bf), fmt, ap);
        va_end(ap);
        return ret;
      }
      static int do_fputs(const char* s, void* bf) {
        return ::fputs(s, unwrap(bf));
      }
      static int do_fputc(int c, void* bf) {
        return ::fputc(c, unwrap(bf));
      }
      static int do_fgetc(void* bf) {
        return ::fgetc(unwrap(bf));
      }
      static size_t do_fread(void* ptr, size_t sz, size_t n, void* bf) {
        return ::fread(ptr, sz, n, unwrap(bf));
      }
      static size_t do_fwrite(const void* ptr, size_t sz, size_t n, void* bf) {
        return ::fwrite(ptr, sz, n, unwrap(bf));
      }
      static int do_fflush(void* bf) {
        return ::fflush(unwrap(bf));
      }
      static int do_fseek(void* bf, long off, int whence) {
        return ::fseek(unwrap(bf), off, whence);
      }
      static int do_ungetc(int c, void* bf) {
        return ::ungetc(c, unwrap(bf));
      }
      static int do_vfprintf(void* bf, const char* fmt, va_list ap) {
        return ::vfprintf(unwrap(bf), fmt, ap);
      }
      static long do_ftell(void* bf) {
        return ::ftell(unwrap(bf));
      }
    };

    struct plt_func_entry { size_t plt_idx; void* func; const char* name; };

    // ========================================================================
    // v1.26.x libPlayFabMultiplayer.so (205 PLT entries, plt_base=0x3d7190)
    // ========================================================================
    static const plt_func_entry known_plt_funcs_v126[] = {
      // Memory operations
      { 4, (void*)memset, "memset" },
      { 5, (void*)memcpy, "memcpy" },
      { 11, (void*)memmove, "memmove" },
      { 12, (void*)memcmp, "memcmp" },
      { 66, (void*)malloc, "malloc" },
      { 69, (void*)calloc, "calloc" },
      { 108, (void*)realloc, "realloc" },
      // File I/O (wrapped: bionic FILE* → glibc FILE* at offset 24)
      { 79, (void*)bionic_file_wrapper::do_fprintf, "fprintf" },
      { 145, (void*)bionic_file_wrapper::do_fwrite, "fwrite" },
      { 148, (void*)bionic_file_wrapper::do_fflush, "fflush" },
      { 192, (void*)bionic_file_wrapper::do_fputc, "fputc" },
      // Threading
      { 109, (void*)pthread_mutex_lock, "pthread_mutex_lock" },
      { 110, (void*)pthread_mutex_unlock, "pthread_mutex_unlock" },
      { 130, (void*)bionic_pthread_cond_signal, "pthread_cond_signal" },
      // Locale
      { 154, (void*)newlocale, "newlocale" },
      { 155, (void*)uselocale, "uselocale" },
      { 161, (void*)freelocale, "freelocale" },
      // String formatting
      { 157, (void*)snprintf, "snprintf" },
      // String-to-number conversions (errno save/clear/check pattern)
      { 115, (void*)strtol, "strtol" },
      { 116, (void*)strtoll, "strtoll" },
      { 117, (void*)strtod, "strtod" },
      { 118, (void*)wcstol, "wcstol" },
      { 119, (void*)wcstoul, "wcstoul" },
      { 120, (void*)wcstol, "wcstol" },
      { 121, (void*)wcstod, "wcstod" },
      { 122, (void*)wcstod, "wcstod" },
      { 123, (void*)wcstold, "wcstold" },
      { 124, (void*)snprintf, "snprintf" },
      { 125, (void*)strtoul, "strtoul" },
      { 126, (void*)wcstoul, "wcstoul" },
      // Multibyte/wide char conversion
      { 113, (void*)mbrtowc, "mbrtowc" },
      // System
      { 190, (void*)syscall, "syscall" },
    };
    static const size_t known_plt_funcs_v126_count = sizeof(known_plt_funcs_v126) / sizeof(known_plt_funcs_v126[0]);

    // ========================================================================
    // v1.21.x libPlayFabMultiplayer.so (523 PLT entries, plt_base=0x408ed0)
    // ========================================================================
    static const plt_func_entry known_plt_funcs[] = {
      // Memory operations
      { 4, (void*)memset, "memset" },
      { 5, (void*)memmove, "memmove" },
      { 9, (void*)free, "free" },
      { 27, (void*)memcpy, "memcpy" },
      { 35, (void*)strlen, "strlen" },
      { 64, (void*)strcmp, "strcmp" },
      { 97, (void*)snprintf, "snprintf" },
      { 103, (void*)malloc, "malloc" },
      { 134, (void*)calloc, "calloc" },
      { 232, (void*)realloc, "realloc" },
      { 512, (void*)posix_memalign, "posix_memalign" },
      // String formatting
      { 47, (void*)sprintf, "sprintf" },
      { 126, (void*)bionic_file_wrapper::do_fprintf, "fprintf" },
      { 274, (void*)snprintf, "snprintf" },
      // String-to-number conversions
      { 41, (void*)strtoull, "strtoull" },
      { 42, (void*)strtoll, "strtoll" },
      { 43, (void*)strtod, "strtod" },
      { 265, (void*)strtoul, "strtoul" },
      { 266, (void*)strtof, "strtof" },
      { 267, (void*)strtold, "strtold" },
      // Wide string operations
      { 146, (void*)swprintf, "swprintf" },
      { 167, (void*)wcslen, "wcslen" },
      { 258, (void*)wmemchr, "wmemchr" },
      { 263, (void*)wmemcmp, "wmemcmp" },
      { 268, (void*)wcstoul, "wcstoul" },
      { 269, (void*)wcstoll, "wcstoll" },
      { 270, (void*)wcstoull, "wcstoull" },
      { 271, (void*)wcstof, "wcstof" },
      { 272, (void*)wcstod, "wcstod" },
      { 273, (void*)wcstold, "wcstold" },
      // File I/O (wrapped: bionic FILE* → glibc FILE* at offset 24)
      { 98, (void*)bionic_file_wrapper::do_fputs, "fputs" },
      { 99, (void*)bionic_file_wrapper::do_fopen, "fopen" },
      { 100, (void*)bionic_file_wrapper::do_fseek, "fseek" },
      { 101, (void*)bionic_file_wrapper::do_ftell, "ftell" },
      { 102, (void*)bionic_file_wrapper::do_fseek, "fseek" },
      { 104, (void*)bionic_file_wrapper::do_fread, "fread" },
      { 106, (void*)bionic_file_wrapper::do_fclose, "fclose" },
      { 345, (void*)bionic_file_wrapper::do_fwrite, "fwrite" },
      { 346, (void*)bionic_file_wrapper::do_fflush, "fflush" },
      { 348, (void*)bionic_file_wrapper::do_fseek, "fseek" },
      { 349, (void*)bionic_file_wrapper::do_ungetc, "ungetc" },
      { 350, (void*)bionic_file_wrapper::do_fgetc, "fgetc" },
      { 351, (void*)bionic_file_wrapper::do_ungetc, "ungetc" },
      { 352, (void*)bionic_file_wrapper::do_fgetc, "fgetc" },
      { 353, (void*)bionic_file_wrapper::do_fputc, "fputc" },
      { 505, (void*)bionic_file_wrapper::do_vfprintf, "vfprintf" },
      { 506, (void*)bionic_file_wrapper::do_fputc, "fputc" },
      { 507, (void*)free, "free" },
      // abort_message helpers
      { 508, (void*)strlen, "strlen" },
      { 509, (void*)dprintf, "dprintf" },
      { 510, (void*)abort, "abort" },
      // Exception handling mutex
      { 519, (void*)pthread_mutex_lock, "pthread_mutex_lock" },
      { 520, (void*)pthread_mutex_unlock, "pthread_mutex_unlock" },
      { 522, (void*)pthread_mutex_lock, "pthread_mutex_lock" },
      // Thread creation
      { 119, (void*)pthread_create, "pthread_create" },
      // Event fd (task queue signaling)
      { 121, (void*)eventfd, "eventfd" },
      // File descriptor operations
      { 138, (void*)close, "close" },
      { 139, (void*)write, "write" },
      { 141, (void*)read, "read" },
      // UUID formatting
      { 145, (void*)snprintf, "snprintf" },
      // Thread-local storage support
      { 128, (void*)pthread_setspecific, "pthread_setspecific" },
      { 292, (void*)pthread_getspecific, "pthread_getspecific" },
      { 312, (void*)pthread_key_create, "pthread_key_create" },
      { 517, (void*)pthread_once, "pthread_once" },
      // Time
      { 110, (void*)localtime, "localtime" },
      { 111, (void*)strftime, "strftime" },
      { 161, (void*)clock_gettime, "clock_gettime" },
      // Mutex (glibc-compatible for NORMAL type on x86_64 LE)
      { 246, (void*)pthread_mutex_lock, "pthread_mutex_lock" },
      { 247, (void*)pthread_mutex_unlock, "pthread_mutex_unlock" },
      { 302, (void*)pthread_mutex_destroy, "pthread_mutex_destroy" },
      { 303, (void*)pthread_mutex_trylock, "pthread_mutex_trylock" },
      { 304, (void*)pthread_mutexattr_init, "pthread_mutexattr_init" },
      { 305, (void*)pthread_mutexattr_settype, "pthread_mutexattr_settype" },
      { 306, (void*)pthread_mutex_init, "pthread_mutex_init" },
      { 307, (void*)pthread_mutexattr_destroy, "pthread_mutexattr_destroy" },
      // Threading
      { 308, (void*)pthread_join, "pthread_join" },
      { 309, (void*)pthread_detach, "pthread_detach" },
      { 311, (void*)nanosleep, "nanosleep" },
      // Condition variables (bionic-compatible, use futex directly)
      { 287, (void*)bionic_pthread_cond_signal, "pthread_cond_destroy" },
      { 288, (void*)bionic_pthread_cond_signal, "pthread_cond_signal" },
      { 289, (void*)bionic_pthread_cond_broadcast, "pthread_cond_broadcast" },
      { 290, (void*)bionic_pthread_cond_wait, "pthread_cond_wait" },
      { 291, (void*)bionic_pthread_cond_timedwait, "pthread_cond_timedwait" },
      // Error handling
      { 284, (void*)posix_strerror_r, "strerror_r" },
      { 285, (void*)abort, "abort" },
      // Locale basics
      { 17, (void*)localeconv, "localeconv" },
      { 310, (void*)sysconf, "sysconf" },
      { 360, (void*)newlocale, "newlocale" },
      { 361, (void*)uselocale, "uselocale" },
      { 376, (void*)strftime, "strftime" },
      { 385, (void*)wcstombs, "wcstombs" },
      { 417, (void*)setlocale, "setlocale" },
      { 419, (void*)freelocale, "freelocale" },
      // Locale-aware collation (from collate_byname)
      { 421, (void*)strcoll_l, "strcoll_l" },
      { 422, (void*)strxfrm_l, "strxfrm_l" },
      { 424, (void*)wcscoll_l, "wcscoll_l" },
      { 425, (void*)wcsxfrm_l, "wcsxfrm_l" },
      // Locale-aware wide char classification (from ctype_byname<wchar_t>)
      { 427, (void*)iswalpha_l, "iswalpha_l" },
      { 437, (void*)iswspace_l, "iswspace_l" },
      { 438, (void*)iswprint_l, "iswprint_l" },
      { 439, (void*)iswcntrl_l, "iswcntrl_l" },
      { 440, (void*)iswupper_l, "iswupper_l" },
      { 441, (void*)iswlower_l, "iswlower_l" },
      { 442, (void*)iswdigit_l, "iswdigit_l" },
      { 443, (void*)iswpunct_l, "iswpunct_l" },
      { 444, (void*)iswxdigit_l, "iswxdigit_l" },
      { 445, (void*)iswblank_l, "iswblank_l" },
      // Locale-aware wide char case conversion (from ctype_byname<wchar_t>)
      { 446, (void*)towupper_l, "towupper_l" },
      { 447, (void*)towlower_l, "towlower_l" },
      // Wide char byte conversion (from ctype_byname<wchar_t> widen/narrow)
      { 448, (void*)btowc, "btowc" },
      { 449, (void*)wctob, "wctob" },
      // Multibyte/wide char conversion (from codecvt/moneypunct/time_get)
      { 378, (void*)mbsrtowcs, "mbsrtowcs" },
      { 452, (void*)wcrtomb, "wcrtomb" },
      { 453, (void*)wcrtomb, "wcrtomb" },
      { 454, (void*)mbrtowc, "mbrtowc" },
      { 455, (void*)mbrtowc, "mbrtowc" },
      { 456, (void*)mbtowc, "mbtowc" },
      { 458, (void*)mbrlen, "mbrlen" },
      // Locale-aware number parsing (from num_get, near __errno)
      { 486, (void*)strtoll_l, "strtoll_l" },
      { 487, (void*)strtoull_l, "strtoull_l" },
      // System
      { 491, (void*)syscall, "syscall" },
    };
    static const size_t known_plt_funcs_count = sizeof(known_plt_funcs) / sizeof(known_plt_funcs[0]);

    ElfW(Addr)* func_entries = plt_got_addr_ + 3; // Skip 3 reserved entries
    size_t fixed_count = 0;
    size_t known_count = 0;
    size_t plt_count = 0;

    // Determine PLT count by finding the PLT section base address.
    // Unresolved .got.plt entries contain raw PLT fallback addresses:
    //   value = PLT_base + 0x10 + index * 0x10 + 6 = PLT_base + 0x16 + index * 0x10
    // We find the first unresolved entry, derive PLT_base, then validate all entries.
    ElfW(Addr) plt_section_base = 0;
    for (size_t i = 0; i < 2048; i++) {
      ElfW(Addr) entry_addr = reinterpret_cast<ElfW(Addr)>(&func_entries[i]);
      ElfW(Addr) value = func_entries[i];

      if (value == 0) break;

      if (resolved_addrs.count(entry_addr)) {
        // Resolved by .rela.plt - valid .got.plt entry
        plt_count = i + 1;
        continue;
      }

      if (value > 0 && value < load_bias) {
        if (plt_section_base == 0) {
          // Derive PLT base from this entry
          plt_section_base = value - 0x16 - i * 0x10;
        }
        // Validate: does this value match expected PLT fallback for index i?
        ElfW(Addr) expected = plt_section_base + 0x16 + i * 0x10;
        if (value != expected) {
          // Not a valid PLT fallback - we've gone past .got.plt
          break;
        }
        plt_count = i + 1;
      } else {
        // Not resolved, not a raw PLT fallback - past .got.plt
        break;
      }
    }

    // Only proceed if we found unresolved entries (plt_section_base != 0).
    // Libraries with all entries resolved don't need fixup.
    if (plt_section_base == 0) {
      // No unresolved PLT entries found - nothing to fix
      goto plt_fixup_done;
    }

    async_safe_format_log(ANDROID_LOG_INFO, "linker",
      "LLD PLT fixup: %zu PLT entries (plt_base=0x%lx) in %s",
      plt_count, (unsigned long)plt_section_base, get_realpath());

    {
    // Select the appropriate PLT function table based on binary version.
    // The PLT indices are specific to each binary version.
    const plt_func_entry* active_table = nullptr;
    size_t active_table_count = 0;

    if (plt_count > 500) {
      // v1.21.x libPlayFabMultiplayer.so (523 PLT entries)
      active_table = known_plt_funcs;
      active_table_count = known_plt_funcs_count;
    } else if (plt_count >= 200 && plt_count <= 210) {
      // v1.26.x libPlayFabMultiplayer.so (205 PLT entries)
      active_table = known_plt_funcs_v126;
      active_table_count = known_plt_funcs_v126_count;
    }

    // Now patch the entries
    for (size_t i = 0; i < plt_count; i++) {
      ElfW(Addr) entry_addr = reinterpret_cast<ElfW(Addr)>(&func_entries[i]);

      // Skip entries already resolved by .rela.plt
      if (resolved_addrs.count(entry_addr)) continue;

      ElfW(Addr) value = func_entries[i];
      if (value > 0 && value < load_bias) {
        // Check if this is a known function
        bool found = false;
        if (active_table) {
          for (size_t j = 0; j < active_table_count; j++) {
            if (i == active_table[j].plt_idx) {
              func_entries[i] = reinterpret_cast<ElfW(Addr)>(active_table[j].func);
              known_count++;
              found = true;
              break;
            }
          }
        }
        if (!found) {
          // Unknown entry - apply load_bias so PLT fallback triggers resolver
          func_entries[i] = value + load_bias;
          fixed_count++;
        }
      }
    }

    if (fixed_count > 0 || known_count > 0) {
      INFO("[ LLD PLT fixup in %s: %zu resolved to known funcs, %zu using resolver ]",
           get_realpath(), known_count, fixed_count);

      // Set up GOT[1] = soinfo pointer (for resolver identification)
      plt_got_addr_[1] = reinterpret_cast<ElfW(Addr)>(this);
      // Set up GOT[2] = PLT resolver trampoline
      plt_got_addr_[2] = reinterpret_cast<ElfW(Addr)>(plt_resolver_trampoline);
    }
    } // end version-specific table scope
plt_fixup_done:
    // Hook __emutls_get_address in libPlayFabMultiplayer.so to automatically
    // sanitize PairIP-encrypted emutls_control structs.
    //
    // PairIP (binary protection) encrypts the .data section. On desktop Linux,
    // PairIP's DT_INIT doesn't run, so emutls_control structs retain encrypted
    // garbage. When __emutls_get_address reads a garbage index, it computes an
    // absurd realloc size and crashes (Signal 6).
    //
    // Instead of patching individual structs (fragile - we might miss some),
    // we hook __emutls_get_address via its GOT entry. Our wrapper detects any
    // corrupted emutls_control (index > 100) and fixes it before calling the
    // real function. This catches ALL encrypted TLS variables automatically.
    //
    // __emutls_get_address: VA 0x404a70, GOT entry at VA 0x41adb8 (PLT[62])
    if (plt_section_base != 0 && plt_count > 500) {
      // Only for libPlayFabMultiplayer.so (523 PLT entries)

      // Step 1: Patch known emutls_control structs directly in .data.
      // This fixes them for BOTH PLT-based and direct calls to __emutls_get_address.
      // emutls_control layout: [0]=size [1]=align [2]=index [3]=value (each 8 bytes)
      static const struct { size_t va; size_t size; } emutls_controls[] = {
        { 0x41fc68, 256 },   // PubSub TLS var 1
        { 0x41fc88, 256 },   // PubSub TLS var 2
        { 0x41fcf8, 256 },   // HttpClient TLS var
        { 0x41fd38, 256 },   // AndroidJniHelper TLS var 1
        { 0x41fd58, 256 },   // AndroidJniHelper TLS var 2
        { 0x41fd78, 256 },   // AndroidJniHelper TLS var 3
        { 0x41ffc0, 128 },   // __cxa_eh_globals (C++ exception handling)
      };
      for (const auto& ec : emutls_controls) {
        uint64_t* control = reinterpret_cast<uint64_t*>(load_bias + ec.va);
        uint64_t old_index = control[2];
        control[0] = ec.size;   // size
        control[1] = 8;         // align
        control[2] = 0;         // index = 0 (force fresh allocation)
        control[3] = 0;         // value = NULL (zero-initialize)
        async_safe_format_log(ANDROID_LOG_INFO, "linker",
          "Fixed emutls_control at VA 0x%lx: old_index=0x%lx, size=%zu",
          (unsigned long)ec.va, (unsigned long)old_index, ec.size);
      }

      // Step 2: Hook __emutls_get_address via GOT to catch any UNKNOWN
      // emutls_control structs we didn't patch above (PLT-based calls only).
      saved_real_emutls = load_bias + 0x404a70;
      ElfW(Addr)* got_emutls = reinterpret_cast<ElfW(Addr)*>(load_bias + 0x41adb8);
      *got_emutls = reinterpret_cast<ElfW(Addr)>(sanitize_emutls_get_address);
      async_safe_format_log(ANDROID_LOG_INFO, "linker",
        "Hooked __emutls_get_address: GOT@0x41adb8 -> sanitizer (real=%p)",
        (void*)saved_real_emutls);

      // Step 3: Patch __emutls_get_address function code with a trampoline.
      // The GOT hook (Step 2) only catches calls through libPlayFabMultiplayer.so's
      // own PLT. But libminecraftpe.so also calls __emutls_get_address via ELF
      // global symbol interposition, using its OWN GOT entry that we can't hook.
      // By patching the function code itself, we catch ALL callers regardless of
      // which library's GOT they use.
      //
      // We overwrite the first 12 bytes of __emutls_get_address:
      //   41 57 41 56 41 55 41 54 53 48 89 fb
      //   (push r15/r14/r13/r12/rbx; mov rbx,rdi)
      // with a jump to an mmap'd trampoline that:
      //   1. Checks if control->index ([rdi+0x10]) > 100 (PairIP-encrypted)
      //   2. If so, fixes the struct (size=1024, align=8, index=0, value=0)
      //   3. Executes the overwritten instructions
      //   4. Jumps back to VA 0x404a7c (instruction after the patch)
      {
        void* trampoline = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                                MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (trampoline == MAP_FAILED) {
          async_safe_format_log(ANDROID_LOG_ERROR, "linker",
            "Failed to mmap trampoline page for emutls code patch");
        } else {
          unsigned char* t = reinterpret_cast<unsigned char*>(trampoline);
          size_t p = 0;

          // cmp qword [rdi+0x10], 100   (check control->index)
          t[p++] = 0x48; t[p++] = 0x83; t[p++] = 0x7f; t[p++] = 0x10; t[p++] = 0x64;
          // jbe skip_fix  (skip 31 bytes if index <= 100)
          t[p++] = 0x76; t[p++] = 0x1f;
          // mov qword [rdi], 0x400      (size = 1024)
          t[p++] = 0x48; t[p++] = 0xc7; t[p++] = 0x07;
          t[p++] = 0x00; t[p++] = 0x04; t[p++] = 0x00; t[p++] = 0x00;
          // mov qword [rdi+8], 8        (align = 8)
          t[p++] = 0x48; t[p++] = 0xc7; t[p++] = 0x47; t[p++] = 0x08;
          t[p++] = 0x08; t[p++] = 0x00; t[p++] = 0x00; t[p++] = 0x00;
          // mov qword [rdi+0x10], 0     (index = 0)
          t[p++] = 0x48; t[p++] = 0xc7; t[p++] = 0x47; t[p++] = 0x10;
          t[p++] = 0x00; t[p++] = 0x00; t[p++] = 0x00; t[p++] = 0x00;
          // mov qword [rdi+0x18], 0     (value = NULL)
          t[p++] = 0x48; t[p++] = 0xc7; t[p++] = 0x47; t[p++] = 0x18;
          t[p++] = 0x00; t[p++] = 0x00; t[p++] = 0x00; t[p++] = 0x00;

          // skip_fix: Execute the overwritten instructions
          t[p++] = 0x41; t[p++] = 0x57;  // push r15
          t[p++] = 0x41; t[p++] = 0x56;  // push r14
          t[p++] = 0x41; t[p++] = 0x55;  // push r13
          t[p++] = 0x41; t[p++] = 0x54;  // push r12
          t[p++] = 0x53;                  // push rbx
          t[p++] = 0x48; t[p++] = 0x89; t[p++] = 0xfb;  // mov rbx, rdi

          // movabs rax, <resume_addr>   (load_bias + 0x404a7c)
          uintptr_t resume_addr = load_bias + 0x404a7c;
          t[p++] = 0x48; t[p++] = 0xb8;
          memcpy(&t[p], &resume_addr, 8); p += 8;
          // jmp rax
          t[p++] = 0xff; t[p++] = 0xe0;

          // Patch the function entry: overwrite first 12 bytes with jump
          uintptr_t func_addr = load_bias + 0x404a70;
          uintptr_t page_start = func_addr & ~(uintptr_t)0xfff;
          uintptr_t page_end = (func_addr + 12 + 0xfff) & ~(uintptr_t)0xfff;

          if (mprotect(reinterpret_cast<void*>(page_start), page_end - page_start,
                       PROT_READ | PROT_WRITE | PROT_EXEC) != 0) {
            async_safe_format_log(ANDROID_LOG_ERROR, "linker",
              "Failed to mprotect __emutls_get_address page for code patching");
          } else {
            unsigned char* func = reinterpret_cast<unsigned char*>(func_addr);
            // movabs rax, <trampoline_addr>
            func[0] = 0x48; func[1] = 0xb8;
            uintptr_t tramp_addr = reinterpret_cast<uintptr_t>(trampoline);
            memcpy(&func[2], &tramp_addr, 8);
            // jmp rax
            func[10] = 0xff; func[11] = 0xe0;

            // Restore page protection
            mprotect(reinterpret_cast<void*>(page_start), page_end - page_start,
                     PROT_READ | PROT_EXEC);

            async_safe_format_log(ANDROID_LOG_INFO, "linker",
              "Patched __emutls_get_address@0x%lx -> trampoline@%p (resume@0x%lx, %zu bytes)",
              (unsigned long)func_addr, trampoline, (unsigned long)resume_addr, p);
          }
        }
      }
    }
  }

  // Workaround for Clang CFI (Control Flow Integrity) in Android binaries.
  // Android binaries compiled with -fsanitize=cfi embed CFI metadata tables
  // at the start of .text. All virtual/indirect calls go through a CFI
  // dispatch function that validates the target and then jumps via r11.
  // On Linux (outside Android), the CFI runtime isn't available, so we
  // detect the dispatch function and patch it with a simple `jmp *%r11`.
  //
  // Detection: scan executable segment for the pattern:
  //   or rsp, rax  (48 09 c4)  -- or --  or rsp, r10  (4c 09 d4)
  //   call <rel32> (e8 xx xx xx xx)
  // All CFI-hardened call sites use this sequence. We filter out PLT
  // targets (which start with FF 25 jmp *[rip+disp]) and look for the
  // most popular non-PLT target containing data (the CFI dispatch).
  for (size_t i = 0; i < phnum; i++) {
    if (phdr[i].p_type != PT_LOAD || !(phdr[i].p_flags & PF_X)) continue;

    unsigned char* seg = reinterpret_cast<unsigned char*>(load_bias + phdr[i].p_vaddr);
    size_t seg_size = phdr[i].p_filesz;
    if (seg_size < 8) break;

    struct { ElfW(Addr) addr; int count; } candidates[16] = {};
    int num_candidates = 0;

    for (size_t off = 0; off + 8 <= seg_size; off++) {
      if ((seg[off] == 0x48 && seg[off+1] == 0x09 && seg[off+2] == 0xc4 && seg[off+3] == 0xe8) ||
          (seg[off] == 0x4c && seg[off+1] == 0x09 && seg[off+2] == 0xd4 && seg[off+3] == 0xe8)) {
        int32_t rel;
        memcpy(&rel, &seg[off + 4], 4);
        ElfW(Addr) target = reinterpret_cast<ElfW(Addr)>(&seg[off + 3]) + 5 + rel;

        // Skip PLT entries (they start with FF 25 = jmp *[rip+disp32])
        unsigned char* target_bytes = reinterpret_cast<unsigned char*>(target);
        if (target_bytes[0] == 0xff && target_bytes[1] == 0x25) {
          off += 7;
          continue;
        }

        bool found = false;
        for (int j = 0; j < num_candidates; j++) {
          if (candidates[j].addr == target) {
            candidates[j].count++;
            found = true;
            break;
          }
        }
        if (!found && num_candidates < 16) {
          candidates[num_candidates].addr = target;
          candidates[num_candidates].count = 1;
          num_candidates++;
        }
        off += 7; // skip past the call instruction
      }
    }

    // Find the most popular non-PLT call target
    ElfW(Addr) cfi_addr = 0;
    int max_count = 0;
    for (int j = 0; j < num_candidates; j++) {
      if (candidates[j].count > max_count) {
        max_count = candidates[j].count;
        cfi_addr = candidates[j].addr;
      }
    }

    // If 50+ calls target the same non-PLT address, it's the CFI dispatch
    if (cfi_addr != 0 && max_count >= 50) {
      unsigned char* cfi = reinterpret_cast<unsigned char*>(cfi_addr);

      // Verify the target doesn't already contain jmp *%r11
      if (cfi[0] != 0x41 || cfi[1] != 0xff || cfi[2] != 0xe3) {
        uintptr_t page = cfi_addr & ~(4096UL - 1);
        if (mprotect(reinterpret_cast<void*>(page), 4096,
                     PROT_READ | PROT_WRITE | PROT_EXEC) == 0) {
          cfi[0] = 0x41;  // jmp *%r11
          cfi[1] = 0xff;
          cfi[2] = 0xe3;
          mprotect(reinterpret_cast<void*>(page), 4096, PROT_READ | PROT_EXEC);
          INFO("[ CFI dispatch patched at %p with jmp *%%r11 (%d call sites) in %s ]",
               reinterpret_cast<void*>(cfi_addr), max_count, get_realpath());
        }
      }
    }
    break; // Only process first executable segment
  }
#endif // __x86_64__

#else
  if (rel_ != nullptr) {
    DEBUG("[ relocating %s rel ]", get_realpath());
    if (!plain_relocate<RelocMode::Typical>(relocator, rel_, rel_count_)) {
      return false;
    }
  }
  if (plt_rel_ != nullptr) {
    DEBUG("[ relocating %s plt rel ]", get_realpath());
    if (!plain_relocate<RelocMode::JumpTable>(relocator, plt_rel_, plt_rel_count_)) {
      return false;
    }
  }
#endif

#if defined(__mips__)
  if (!mips_relocate_got(version_tracker, global_group, local_group)) {
    return false;
  }
#endif

  // Once the tlsdesc_args_ vector's size is finalized, we can write the addresses of its elements
  // into the TLSDESC relocations.
#if 0 && defined(__aarch64__)
  // Bionic currently only implements TLSDESC for arm64.
  for (const std::pair<TlsDescriptor*, size_t>& pair : relocator.deferred_tlsdesc_relocs) {
    TlsDescriptor* desc = pair.first;
    desc->func = tlsdesc_resolver_dynamic;
    desc->arg = reinterpret_cast<size_t>(&tlsdesc_args_[pair.second]);
  }
#endif

  return true;
}
