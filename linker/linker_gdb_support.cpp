/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "linker_gdb_support.h"

#include <pthread.h>

#include "private/ScopedPthreadMutexLocker.h"

#include <sys/auxv.h>
#include <linux/auxvec.h>
#include <cstddef>

// has to be exactly this or it breaks, also don't use it since it's not what gdb uses...
struct r_debug _r_debug __attribute__((nocommon, section(".r_debug")));

namespace ELF {
    using Phdr = Elf64_Phdr;
    using Dyn = Elf64_Dyn;
}

// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// Retrieve the address of the current process' dynamic section.
bool FindElfDynamicSection(size_t* dynamic_address, size_t* dynamic_size) {
    // Use getauxval() to get the address and size of the executable's
    // program table entry. Note: On Android, getauxval() is only available
    // starting with API level 18.
    const size_t phdr_num = static_cast<size_t>(getauxval(AT_PHNUM));
    const auto* phdr_table = reinterpret_cast<ELF::Phdr*>(getauxval(AT_PHDR));
    if (!phdr_table) {
        return false;
    }
    // NOTE: The program header table contains the following interesting entries:
    // - A PT_PHDR entry corresponding to the program header table itself!
    // - A PT_DYNAMIC entry corresponding to the dynamic section.
    const ELF::Phdr* pt_phdr = nullptr;
    const ELF::Phdr* pt_dynamic = nullptr;
    for (size_t n = 0; n < phdr_num; ++n) {
        const ELF::Phdr* phdr = &phdr_table[n];
        if (phdr->p_type == PT_PHDR && !pt_phdr)
            pt_phdr = phdr;
        else if (phdr->p_type == PT_DYNAMIC && !pt_dynamic)
            pt_dynamic = phdr;
    }
    if (!pt_phdr) {
        return false;
    }
    if (!pt_dynamic) {
        return false;
    }
    auto pt_hdr_address = reinterpret_cast<ptrdiff_t>(pt_phdr);
    auto load_bias = pt_hdr_address - static_cast<ptrdiff_t>(pt_phdr->p_vaddr);
    *dynamic_address = static_cast<size_t>(load_bias + pt_dynamic->p_vaddr);
    *dynamic_size = static_cast<size_t>(pt_dynamic->p_memsz);
    return true;
}
static void *GetRDebug() {
    size_t dynamic_addr = 0;
    size_t dynamic_size = 0;
    if (!FindElfDynamicSection(&dynamic_addr, &dynamic_size)) {
        return nullptr;
    }
    // Parse the dynamic table and find the DT_DEBUG entry.
    const ELF::Dyn* dyn_section = reinterpret_cast<const ELF::Dyn*>(dynamic_addr);
    while (dynamic_size >= sizeof(*dyn_section)) {
        if (dyn_section->d_tag == DT_DEBUG) {
            // Found it!
            if (dyn_section->d_un.d_ptr) {
                return reinterpret_cast<r_debug*>(dyn_section->d_un.d_ptr);
            }
        }
        dyn_section++;
        dynamic_size -= sizeof(*dyn_section);
    }

    return nullptr;
}

static struct r_debug *g__r_debug = (struct r_debug*) GetRDebug();
static pthread_mutex_t g__r_debug_mutex = PTHREAD_MUTEX_INITIALIZER;
static link_map* r_debug_tail = nullptr;
struct link_map r_debug_start = {
        0, "linker", nullptr, nullptr, nullptr
};

// This function is an empty stub where GDB locates a breakpoint to get notified
// about linker activity.
extern "C"
void __attribute__((noinline)) __attribute__((visibility("default"))) rtld_db_dlactivity();


void init_rdebug() {
    if (r_debug_tail != nullptr)
        return;
    auto saved_map = g__r_debug->r_map->l_next;

    g__r_debug->r_state = r_debug::RT_DELETE;
    rtld_db_dlactivity();
    g__r_debug->r_map = nullptr;
    g__r_debug->r_state = r_debug::RT_CONSISTENT;
    rtld_db_dlactivity();

    g__r_debug->r_state = r_debug::RT_ADD;
    rtld_db_dlactivity();

    saved_map->l_prev = &r_debug_start;
    r_debug_start.l_next = saved_map;
    g__r_debug->r_map = &r_debug_start;
    r_debug_tail = &r_debug_start;

    g__r_debug->r_state = r_debug::RT_CONSISTENT;
    rtld_db_dlactivity();
}

void insert_link_map_into_debug_map(link_map* map) {
  // Stick the new library at the end of the list.
  // gdb tends to care more about libc than it does
  // about leaf libraries, and ordering it this way
  // reduces the back-and-forth over the wire.
  init_rdebug();
  if (r_debug_tail != nullptr) {
    map->l_next = r_debug_tail->l_next;
    map->l_next->l_prev = map;
    r_debug_tail->l_next = map;
    map->l_prev = r_debug_tail;
  }
  r_debug_tail = map;
}

void remove_link_map_from_debug_map(link_map* map) {
  if (r_debug_tail == map) {
    r_debug_tail = map->l_prev;
  }

  if (map->l_prev) {
    map->l_prev->l_next = map->l_next;
  }
  if (map->l_next) {
    map->l_next->l_prev = map->l_prev;
  }
}

void notify_gdb_of_load(link_map* map) {
  ScopedPthreadMutexLocker locker(&g__r_debug_mutex);

  g__r_debug->r_state = r_debug::RT_ADD;
  rtld_db_dlactivity();

  insert_link_map_into_debug_map(map);

  g__r_debug->r_state = r_debug::RT_CONSISTENT;
  rtld_db_dlactivity();
}

void notify_gdb_of_unload(link_map* map) {
  ScopedPthreadMutexLocker locker(&g__r_debug_mutex);

  g__r_debug->r_state = r_debug::RT_DELETE;
  rtld_db_dlactivity();

  remove_link_map_from_debug_map(map);

  g__r_debug->r_state = r_debug::RT_CONSISTENT;
  rtld_db_dlactivity();
}

void notify_gdb_of_libraries() {
  g__r_debug->r_state = r_debug::RT_ADD;
  rtld_db_dlactivity();
  g__r_debug->r_state = r_debug::RT_CONSISTENT;
  rtld_db_dlactivity();
}

