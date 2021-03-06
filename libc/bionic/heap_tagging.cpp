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

#include "heap_tagging.h"
#include "malloc_common.h"
#include "malloc_tagged_pointers.h"

#include <platform/bionic/malloc.h>
#include <platform/bionic/mte_kernel.h>

static HeapTaggingLevel heap_tagging_level = M_HEAP_TAGGING_LEVEL_NONE;

void SetDefaultHeapTaggingLevel() {
  // Allow the kernel to accept tagged pointers in syscall arguments. This is a no-op (kernel
  // returns -EINVAL) if the kernel doesn't understand the prctl.
#if defined(__aarch64__)
#define PR_SET_TAGGED_ADDR_CTRL 55
#define PR_TAGGED_ADDR_ENABLE (1UL << 0)
#ifdef ANDROID_EXPERIMENTAL_MTE
  // First, try enabling MTE in asynchronous mode, with tag 0 excluded. This will fail if the kernel
  // or hardware doesn't support MTE, and we will fall back to just enabling tagged pointers in
  // syscall arguments.
  if (prctl(PR_SET_TAGGED_ADDR_CTRL,
            PR_TAGGED_ADDR_ENABLE | PR_MTE_TCF_ASYNC | (1 << PR_MTE_EXCL_SHIFT), 0, 0, 0) == 0) {
    return;
  }
#endif // ANDROID_EXPERIMENTAL_MTE

  if (prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE, 0, 0, 0) == 0) {
    heap_tagging_level = M_HEAP_TAGGING_LEVEL_TBI;
    __libc_globals.mutate([](libc_globals* globals) {
      globals->heap_pointer_tag = reinterpret_cast<uintptr_t>(POINTER_TAG) << TAG_SHIFT;
    });
  }
#endif  // aarch64
}

bool SetHeapTaggingLevel(void* arg, size_t arg_size) {
  if (arg_size != sizeof(HeapTaggingLevel)) {
    return false;
  }

  auto tag_level = *reinterpret_cast<HeapTaggingLevel*>(arg);
  switch (tag_level) {
    case M_HEAP_TAGGING_LEVEL_NONE:
      break;
    case M_HEAP_TAGGING_LEVEL_TBI:
      if (heap_tagging_level == M_HEAP_TAGGING_LEVEL_NONE) {
        error_log(
            "SetHeapTaggingLevel: re-enabling tagging after it was disabled is not supported");
        return false;
      }
      break;
    default:
      error_log("SetHeapTaggingLevel: unknown tagging level");
      return false;
  }
  heap_tagging_level = tag_level;
  info_log("SetHeapTaggingLevel: tag level set to %d", tag_level);

  if (heap_tagging_level == M_HEAP_TAGGING_LEVEL_NONE && __libc_globals->heap_pointer_tag != 0) {
    __libc_globals.mutate([](libc_globals* globals) { globals->heap_pointer_tag = 0; });
  }

  return true;
}
