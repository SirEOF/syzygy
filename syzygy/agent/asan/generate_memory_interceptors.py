# Copyright 2015 Google Inc. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import datetime
import os.path
import re
import string


# Header for an assembly file.
_ASM_HEADER = """\
; Copyright {year} Google Inc. All Rights Reserved.
;
; Licensed under the Apache License, Version 2.0 (the "License");
; you may not use this file except in compliance with the License.
; You may obtain a copy of the License at
;
;     http://www.apache.org/licenses/LICENSE-2.0
;
; Unless required by applicable law or agreed to in writing, software
; distributed under the License is distributed on an "AS IS" BASIS,
; WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
; See the License for the specific language governing permissions and
; limitations under the License.

; This file is generated by {basename}, DO NOT MODIFY.
; Regenerate this file by running syzygy/agent/asan/generate_files.bat.

.386
.MODEL FLAT, C

.CODE

; Allow section and label names to begin with a leading period.
OPTION DOTNAME
"""

# Trailer for an assembly file.
_ASM_TRAILER = """\
END
"""

_REDIRECTORS_EXTERN = """\
; Declare the tail function all the stubs direct to.
EXTERN C asan_redirect_tail:PROC
"""


_REDIRECTORS_PROC_HEADER = """\

; Declare a single top-level function to prevent identical code folding from
; folding the redirectors into one. Each redirector simply calls through to
; the tail function. This allows the tail function to trivially compute the
; redirector's address, which is used to identify the invoked redirector.
asan_redirectors PROC

; Adds a NOP at the beginning of this function to make this work when using
; incremental linking. Every reference to the first probe will otherwise be
; replaced by a jump to a thunk.
nop
"""

_REDIRECTORS_PROC_TRAILER = """\
asan_redirectors ENDP
"""


# Declares external functions and data required by the probe implementations.
# Args:
#   shadow: The name of the variable housing the shadow memory.
_INTERCEPTORS_PREAMBLE = """\
; Declare the global shadow memory array that probes refer to.
EXTERN C {shadow}:FAR

; Declare the string checking helper function.
EXTERN C asan_check_strings_memory_accesses:PROC

; Declare the redirect function.
EXTERN C asan_redirect_stub_entry:PROC

; Declare the error handling funtion.
EXTERN C asan_report_bad_memory_access:PROC

; Declares the symbols that this compiland exports.
PUBLIC asan_no_check
PUBLIC asan_string_no_check
PUBLIC asan_redirect_tail
PUBLIC asan_shadow_references"""


_INTERCEPTORS_SEGMENT_HEADER = """\
; Create a new text segment to house the memory interceptors.
.probes SEGMENT PAGE PUBLIC READ EXECUTE 'CODE'
"""

_INTERCEPTORS_SEGMENT_FOOTER = """\
.probes ENDS
"""


_RDATA_SEGMENT_HEADER = """\
; Start writing to the read-only .rdata segment.
.rdata SEGMENT PAGE PUBLIC READ 'DATA'
"""


_RDATA_SEGMENT_FOOTER = """\
.rdata ENDS
"""


# Snippets relating to shadow memory.
_SHADOW = "asan_memory_interceptors_shadow_memory"
_SHADOW_REFERENCE_TABLE_HEADER = """\
; This is a null-terminated table of pointers to all shadow memory references.
; This is emitted so that the shadow memory pointer may be rewritten at
; runtime by the dynamic RTL.
ALIGN 4
asan_shadow_references LABEL FAR"""
_SHADOW_REFERENCE_TABLE_ENTRY = """\
  DWORD shadow_reference_{shadow_index!s} - 4"""
_SHADOW_REFERENCE_TABLE_FOOTER = """\
  DWORD 0
"""


# Generates the single-instance assembly stubs.
_INTERCEPTORS_GLOBAL_FUNCTIONS = """\
; On entry, the address to check is in EDX and the previous contents of
; EDX are on stack. On exit the previous contents of EDX have been restored
; and popped off the stack. This function modifies no other registers,
; in particular it saves and restores EFLAGS.
ALIGN 16
asan_no_check PROC
  ; Restore EDX.
  mov edx, DWORD PTR[esp + 4]
  ; And return.
  ret 4
asan_no_check ENDP

; No state is saved for string instructions.
ALIGN 16
asan_string_no_check PROC
  ; Just return.
  ret
asan_string_no_check ENDP

; On entry, the address to check is in EDX and the stack has:
; - previous contents of EDX.
; - return address to original caller.
; - return address to redirection stub.
ALIGN 16
asan_redirect_tail PROC
  ; Prologue, save context.
  pushfd
  pushad

  ; Normalize the string operation direction.
  cld

  ; Compute the address of the calling function and push it.
  mov eax, DWORD PTR[esp + 9 * 4]
  sub eax, 5  ; Length of call instruction.
  push eax
  ; Push the original caller's address.
  push DWORD PTR[esp + 11 * 4]
  call asan_redirect_stub_entry
  ; Clean arguments off the stack.
  add esp, 8

  ; Overwrite access_size with the stub to return to.
  mov DWORD PTR[esp + 9 * 4], eax

  ; Restore context.
  popad
  popfd

  ; return to the stashed stub.
  ret
asan_redirect_tail ENDP
"""


# Starts by saving EAX onto the stack and then loads the value of
# the flags into it.
#
# This is a trick for efficient saving/restoring part of the flags register.
# See http://blog.freearrow.com/archives/396.
# Flags (bits 16-31) probably need a pipeline flush on update (POPFD). Thus,
# using LAHF/SAHF instead gives better performance.
#   PUSHFD/POPFD: 23.314684 ticks
#   LAHF/SAHF:     8.838665 ticks
_SAVE_EFLAGS = """\
  ; Save the EFLAGS.
  push eax
  lahf
  seto al"""


# Restores the flags.
#
# The previous flags value is assumed to be in EAX and we expect to have the
# previous value of EAX on the top of the stack.
# AL is set to 1 if the overflow flag was set before the call to our hook, 0
# otherwise. We add 0x7F to it so it'll restore the flag. Then we restore the
# low bytes of the flags and EAX.
_RESTORE_EFLAGS = """\
  ; Restore the EFLAGS.
  add al, 7Fh
  sahf
  pop eax"""


_2GB_CHECK = """\
  ; Divide by 8 to convert the address to a shadow index. This is a signed
  ; operation so the sign bit will stay positive if the address is above the 2GB
  ; threshold, and the check will fail.
  sar edx, 3
  js report_failure_{probe_index}"""


_4GB_CHECK = """\
  ; Divide by 8 to convert the address to a shadow index. No range check is
  ; needed as the address space is 4GB.
  shr edx, 3"""


# The common part of the fast path shared between the different
# implementations of the hooks.
#
# This does the following:
#   - Saves the memory location in EDX for the slow path.
#   - Does an address check if neccessary.
#   - Checks for zero shadow for this memory location. We use the cmp
#       instruction so it'll set the sign flag if the upper bit of the shadow
#       value of this memory location is set to 1.
#   - If the shadow byte is not equal to zero then it jumps to the slow path.
#   - Otherwise it removes the memory location from the top of the stack.
_FAST_PATH = """\
  push edx
  {range_check}
  movzx edx, BYTE PTR[edx + {shadow}]
  ; This is a label to the previous shadow memory reference. It will be
  ; referenced by the table at the end of the 'asan_probes' procedure.
shadow_reference_{shadow_index!s} LABEL NEAR
  cmp dl, 0
  jnz check_access_slow_{probe_index}
  add esp, 4"""


# This is the common part of the slow path shared between the different
# implementations of the hooks.
#
# The memory location is expected to be on top of the stack and the shadow
# value for it is assumed to be in DL at this point.
# This also relies on the fact that the shadow non accessible byte mask has
# its upper bit set to 1 and that we jump to this macro after doing a
# "cmp shadow_byte, 0", so the sign flag would be set to 1 if the value isn't
# accessible.
# We inline the Shadow::IsAccessible function for performance reasons.
# This function does the following:
#   - Checks if this byte is accessible and jumps to the error path if it's
#     not.
#   - Removes the memory location from the top of the stack.
_SLOW_PATH = """\
  js report_failure_{probe_index}
  mov dh, BYTE PTR[esp]
  and dh, 7
  cmp dh, dl
  jae report_failure_{probe_index}
  add esp, 4"""


# The error path.
#
# It expects to have the previous value of EDX at [ESP + 4] and the address
# of the faulty instruction at [ESP].
# This macro takes care of saving and restoring the flags.
_ERROR_PATH ="""\
  ; Restore original value of EDX, and put memory location on stack.
  xchg edx, DWORD PTR[esp + 4]
  ; Create an Asan registers context on the stack.
  pushfd
  pushad
  ; Fix the original value of ESP in the Asan registers context.
  ; Removing 12 bytes (e.g. EFLAGS / EIP / Original EDX).
  add DWORD PTR[esp + 12], 12
  ; Push ARG4: the address of Asan context on stack.
  push esp
  ; Push ARG3: the access size.
  push {access_size}
  ; Push ARG2: the access type.
  push {access_mode_value}
  ; Push ARG1: the memory location.
  push DWORD PTR[esp + 52]
  call asan_report_bad_memory_access
  ; Remove 4 x ARG on stack.
  add esp, 16
  ; Restore original registers.
  popad
  popfd
  ; Return and remove memory location on stack.
  ret 4"""


# Collects the above macros and bundles them up in a dictionary so they can be
# easily expanded by the string format functions.
_MACROS = {
  "AsanSaveEflags": _SAVE_EFLAGS,
  "AsanRestoreEflags": _RESTORE_EFLAGS,
  "AsanFastPath": _FAST_PATH,
  "AsanSlowPath": _SLOW_PATH,
  "AsanErrorPath": _ERROR_PATH,
}


# Generates the Asan check access functions.
#
# The name of the generated method will be
# asan_check_(@p access_size)_byte_(@p access_mode_str)().
#
# Args:
#   access_size: The size of the access (in byte).
#   access_mode_str: The string representing the access mode (read_access
#       or write_access).
#   access_mode_value: The internal value representing this kind of
#       access.
#   probe_index: The index of the probe function. Used to mangle internal labels
#       so that they are unique to this probes implementation.
_CHECK_FUNCTION = """\
; On entry, the address to check is in EDX and the previous contents of
; EDX are on stack. On exit the previous contents of EDX have been restored
; and popped off the stack. This function modifies no other registers,
; in particular it saves and restores EFLAGS.
ALIGN 16
asan_check_{access_size}_byte_{access_mode_str}_{mem_model} PROC  \
; Probe #{probe_index}.
  {AsanSaveEflags}
  {AsanFastPath}
  ; Restore original EDX.
  mov edx, DWORD PTR[esp + 8]
  {AsanRestoreEflags}
  ret 4
check_access_slow_{probe_index} LABEL NEAR
  {AsanSlowPath}
  ; Restore original EDX.
  mov edx, DWORD PTR[esp + 8]
  {AsanRestoreEflags}
  ret 4
report_failure_{probe_index} LABEL NEAR
  ; Restore memory location in EDX.
  pop edx
  {AsanRestoreEflags}
  {AsanErrorPath}
asan_check_{access_size}_byte_{access_mode_str}_{mem_model} ENDP
"""


# Declare the check access function public label.
_CHECK_FUNCTION_DECL = """\
PUBLIC asan_check_{access_size}_byte_{access_mode_str}_{mem_model}  ; Probe \
#{probe_index}."""


# Generates a variant of the Asan check access functions that don't save
# the flags.
#
# The name of the generated method will be
# asan_check_(@p access_size)_byte_(@p access_mode_str)_no_flags().
#
# Args:
#   access_size: The size of the access (in byte).
#   access_mode_str: The string representing the access mode (read_access
#       or write_access).
#   access_mode_value: The internal value representing this kind of access.
#   probe_index: The index of the probe function. Used to mangle internal labels
#       so that they are unique to this probes implementation.
# Note: Calling this function may alter the EFLAGS register only.
_CHECK_FUNCTION_NO_FLAGS = """\
; On entry, the address to check is in EDX and the previous contents of
; EDX are on stack. On exit the previous contents of EDX have been restored
; and popped off the stack. This function may modify EFLAGS, but preserves
; all other registers.
ALIGN 16
asan_check_{access_size}_byte_{access_mode_str}_no_flags_{mem_model} PROC  \
; Probe #{probe_index}.
  {AsanFastPath}
  ; Restore original EDX.
  mov edx, DWORD PTR[esp + 4]
  ret 4
check_access_slow_{probe_index} LABEL NEAR
  {AsanSlowPath}
  ; Restore original EDX.
  mov edx, DWORD PTR[esp + 4]
  ret 4
report_failure_{probe_index} LABEL NEAR
  ; Restore memory location in EDX.
  pop edx
  {AsanErrorPath}
asan_check_{access_size}_byte_{access_mode_str}_no_flags_{mem_model} ENDP
"""


# Declare the check access function public label.
_CHECK_FUNCTION_NO_FLAGS_DECL = """\
PUBLIC asan_check_{access_size}_byte_{access_mode_str}_no_flags_{mem_model}  \
; Probe #{probe_index}."""


# Generates the Asan memory accessor redirector stubs.
#
# The name of the generated method will be
# asan_redirect_(@p access_size)_byte_(@p access_mode_str)(@p suffix)().
#
# Args:
#   access_size: The size of the access (in byte).
#   access_mode_str: The string representing the access mode (read_access
#       or write_access).
#   access_mode_value: The internal value representing this kind of
#       access.
#   suffix: The suffix - if any - for this function name
_REDIRECT_FUNCTION = """\
asan_redirect_{access_size}_byte_{access_mode_str}{suffix} LABEL PROC
  call asan_redirect_tail"""


# Declare the public label.
_REDIRECT_FUNCTION_DECL = """\
PUBLIC asan_redirect_{access_size}_byte_{access_mode_str}{suffix}"""


# Generates the Asan check access functions for a string instruction.
#
# The name of the generated method will be
# asan_check_(@p prefix)(@p access_size)_byte_(@p inst)_access().
#
# Args:
#   inst: The instruction mnemonic.
#   prefix: The prefix of the instruction (repz or nothing).
#   counter: The number of times the instruction must be executed (ECX).
#       It may be a register or a constant.
#   dst:_mode The memory access mode for destination (EDI).
#   src:_mode The memory access mode for destination (ESI).
#   access:_size The size of the access (in byte).
#   compare: A flag to enable shortcut execution by comparing memory
#       contents.
_CHECK_STRINGS = """\
ALIGN 16
asan_check{prefix}{access_size}_byte_{func}_access PROC  ; Probe #{probe_index}.
  ; Prologue, save context.
  pushfd
  pushad
  ; Fix the original value of ESP in the Asan registers context.
  ; Removing 8 bytes (e.g.EFLAGS / EIP was on stack).
  add DWORD PTR[esp + 12], 8
  ; Setup increment in EBX (depends on direction flag in EFLAGS).
  mov ebx, {access_size}
  pushfd
  pop eax
  test eax, 400h
  jz skip_neg_direction_{probe_index}
  neg ebx
skip_neg_direction_{probe_index} LABEL NEAR
  ; By standard calling convention, direction flag must be forward.
  cld
  ; Push ARG(context), the Asan registers context.
  push esp
  ; Push ARG(compare), shortcut when memory contents differ.
  push {compare}
  ; Push ARG(increment), increment for EDI/EDI.
  push ebx
  ; Push ARG(access_size), the access size.
  push {access_size}
  ; Push ARG(length), the number of memory accesses.
  push {counter}
  ; Push ARG(src_access_mode), source access type.
  push {src_mode}
  ; Push ARG(src), the source pointer.
  push esi
  ; Push ARG(dst_access_mode), destination access type.
  push {dst_mode}
  ; Push ARG(dst), the destination pointer.
  push edi
  ; Call the generic check strings function.
  call asan_check_strings_memory_accesses
  add esp, 36
  ; Epilogue, restore context.
  popad
  popfd
  ret
asan_check{prefix}{access_size}_byte_{func}_access ENDP
"""


# Declare the string checking probe public label.
_CHECK_STRINGS_DECL = """\
PUBLIC asan_check{prefix}{access_size}_byte_{func}_access  ; Probe \
#{probe_index}."""


# Generates the Asan string memory accessor redirector stubs.
#
# The name of the generated method will be
# asan_redirect_(@p prefix)(@p access_size)_byte_(@p inst)_access().
#
# Args:
#     inst: The instruction mnemonic.
#     prefix: The prefix of the instruction (repz or nothing).
#     counter: The number of times the instruction must be executed (ECX).
#         It may be a register or a constant.
#     dst:_mode The memory access mode for destination (EDI).
#     src:_mode The memory access mode for destination (ESI).
#     access:_size The size of the access (in byte).
#     compare: A flag to enable shortcut execution by comparing memory
#         contents.
_STRING_REDIRECT_FUNCTION = """\
asan_redirect{prefix}{access_size}_byte_{func}_access LABEL PROC
  call asan_redirect_tail"""

# Declare the public label.
_STRING_REDIRECT_FUNCTION_DECL = """\
PUBLIC asan_redirect{prefix}{access_size}_byte_{func}_access"""


class MacroAssembler(string.Formatter):
  """A formatter specialization to inject the AsanXXX macros and make
  them easier to use."""

  def parse(self, str):
    """Override to trim whitespace on empty trailing line."""
    for (lit, fld, fmt, conv) in super(MacroAssembler, self).parse(str):
      # Strip trailing whitespace from the previous literal to allow natural
      # use of AsanXXX macros.
      m = re.match('^(.*\n)( +)$', lit)
      if m:
        lit = m.group(0)
      yield((lit, fld, fmt, conv))

  def get_value(self, key, args, kwargs):
    """Override to inject macro definitions."""
    if key in _MACROS:
      macro = _MACROS[key].format(*args, **kwargs)
      # Trim leading whitespace to allow natural use of AsanXXX macros.
      macro = macro.lstrip()
      return macro
    return super(MacroAssembler, self).get_value(key, args, kwargs)


# Access sizes for the memory accessors generated.
_ACCESS_SIZES = (1, 2, 4, 8, 10, 16, 32)


# These values must correspond to those defined in the agent::asan::AccessMode
# enum. See syzygy/agent/asan/error_info.h.
_ASAN_READ_ACCESS = 0
_ASAN_WRITE_ACCESS = 1
_ASAN_UNKNOWN_ACCESS = 2


# Access modes for the memory accessors generated.
_ACCESS_MODES = [
    ('read_access', _ASAN_READ_ACCESS),
    ('write_access', _ASAN_WRITE_ACCESS),
]


# Memory models for the generated accessors, and the associated address range
# checks to insert.
_MEMORY_MODELS = [
    ('2gb', _2GB_CHECK.lstrip()),
    ('4gb', _4GB_CHECK.lstrip()),
]


# The string accessors generated.
_STRING_ACCESSORS = [
    ("cmps", "_repz_", "ecx", _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 4, 1),
    ("cmps", "_repz_", "ecx", _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 2, 1),
    ("cmps", "_repz_", "ecx", _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 1, 1),
    ("cmps", "_", 1, _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 4, 1),
    ("cmps", "_", 1, _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 2, 1),
    ("cmps", "_", 1, _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 1, 1),
    ("lods", "_repz_", "ecx", _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 4, 1),
    ("lods", "_repz_", "ecx", _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 2, 1),
    ("lods", "_repz_", "ecx", _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 1, 1),
    ("lods", "_", 1, _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 4, 1),
    ("lods", "_", 1, _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 2, 1),
    ("lods", "_", 1, _ASAN_READ_ACCESS, _ASAN_READ_ACCESS, 1, 1),
    ("movs", "_repz_", "ecx", _ASAN_WRITE_ACCESS, _ASAN_READ_ACCESS, 4, 0),
    ("movs", "_repz_", "ecx", _ASAN_WRITE_ACCESS, _ASAN_READ_ACCESS, 2, 0),
    ("movs", "_repz_", "ecx", _ASAN_WRITE_ACCESS, _ASAN_READ_ACCESS, 1, 0),
    ("movs", "_", 1, _ASAN_WRITE_ACCESS, _ASAN_READ_ACCESS, 4, 0),
    ("movs", "_", 1, _ASAN_WRITE_ACCESS, _ASAN_READ_ACCESS, 2, 0),
    ("movs", "_", 1, _ASAN_WRITE_ACCESS, _ASAN_READ_ACCESS, 1, 0),
    ("stos", "_repz_", "ecx", _ASAN_WRITE_ACCESS, _ASAN_UNKNOWN_ACCESS, 4, 0),
    ("stos", "_repz_", "ecx", _ASAN_WRITE_ACCESS, _ASAN_UNKNOWN_ACCESS, 2, 0),
    ("stos", "_repz_", "ecx", _ASAN_WRITE_ACCESS, _ASAN_UNKNOWN_ACCESS, 1, 0),
    ("stos", "_", 1, _ASAN_WRITE_ACCESS, _ASAN_UNKNOWN_ACCESS, 4, 0),
    ("stos", "_", 1, _ASAN_WRITE_ACCESS, _ASAN_UNKNOWN_ACCESS, 2, 0),
    ("stos", "_", 1, _ASAN_WRITE_ACCESS, _ASAN_UNKNOWN_ACCESS, 1, 0),
]


class ToStringCounter(object):
  """A helper class that counts how often it is converted to a string."""

  def __init__(self, count=0):
    self._count = count

  def __str__(self):
    self._count += 1
    return str(self._count - 1)

  def count(self):
    return self._count


def _IterateOverInterceptors(parts,
                             formatter,
                             format,
                             format_no_flags,
                             probe_index=0,
                             shadow_index=0):
  """Helper for _GenerateInterceptorsAsmFile."""
  f = formatter

  # This variable hides a counter which automatically increments for every
  # reference made to it. This allows the probes to use arbitrarily many
  # references to the shadow memory and the generator will implicitly track
  # these and emit a table entry per reference.
  #
  # For this mechanism to work reliably all references to 'shadow_index' in the
  # formatting strings must be specified using '{shadow_index!s}'. This
  # guarantees that the __str__ method of the ToStringCounter instance will be
  # called.
  shadow_index = ToStringCounter(shadow_index)

  for mem_model, range_check in _MEMORY_MODELS:
    # Iterate over the probes that have flags.
    for access_size in _ACCESS_SIZES:
      for access, access_name in _ACCESS_MODES:
        formatted_range_check = f.format(range_check, probe_index=probe_index)
        parts.append(f.format(format,
                              access_size=access_size,
                              access_mode_str=access,
                              access_mode_value=access_name,
                              mem_model=mem_model,
                              probe_index=probe_index,
                              range_check=formatted_range_check,
                              shadow=_SHADOW,
                              shadow_index=shadow_index))
        probe_index += 1

    for access_size in _ACCESS_SIZES:
      for access, access_name in _ACCESS_MODES:
        formatted_range_check = f.format(range_check, probe_index=probe_index)
        parts.append(f.format(format_no_flags,
                              access_size=access_size,
                              access_mode_str=access,
                              access_mode_value=access_name,
                              mem_model=mem_model,
                              probe_index=probe_index,
                              range_check=formatted_range_check,
                              shadow=_SHADOW,
                              shadow_index=shadow_index))
        probe_index += 1

  # Return the probe and shadow memory reference counts.
  return (probe_index, shadow_index.count())


def _IterateOverStringInterceptors(parts, formatter, format, probe_index=0):
  """Helper for _GenerateInterceptorsAsmFile."""
  for (fn, p, c, dst_mode, src_mode, size, compare) in _STRING_ACCESSORS:
    parts.append(formatter.format(format,
                                  access_size=size,
                                  compare=compare,
                                  counter=c,
                                  dst_mode=dst_mode,
                                  func=fn,
                                  prefix=p,
                                  probe_index=probe_index,
                                  src_mode=src_mode))
    probe_index += 1

  return probe_index


def _GenerateInterceptorsAsmFile():
  f = MacroAssembler()
  parts = [f.format(_ASM_HEADER,
                    basename=os.path.basename(__file__),
                    year=datetime.datetime.now().year)]

  parts.append(f.format(_INTERCEPTORS_PREAMBLE, shadow=_SHADOW))

  probe_index = 0
  shadow_index = 0

  # Generate the block of public label declarations.
  (probe_index, shadow_index) = _IterateOverInterceptors(parts, f,
      _CHECK_FUNCTION_DECL, _CHECK_FUNCTION_NO_FLAGS_DECL,
      probe_index=probe_index, shadow_index=shadow_index)
  probe_index = _IterateOverStringInterceptors(parts, f, _CHECK_STRINGS_DECL,
      probe_index=probe_index)
  parts.append('')

  # Place all of the probe functions in a custom segment.
  parts.append(f.format(_INTERCEPTORS_SEGMENT_HEADER))

  # Generate the single-instance functions.
  parts.append(f.format(_INTERCEPTORS_GLOBAL_FUNCTIONS))

  # TODO(siggi): Think about the best way to allow the stubs to communicate
  #     their own and their alternative identities to the bottleneck function.
  #     A particularly nice way is to generate an array of N-tuples that can
  #     be used when patching up IATs, where the redirector and the
  #     alternatives consume a row each. Passing in the array entry to the
  #     bottleneck is then the nicest, but the easiest is probably to pass in
  #     the redirector function itself...

  # Reset the probe and shadow indices.
  probe_index = 0
  shadow_index = 0

  # Output the actual interceptors themselves
  (probe_index, shadow_index) = _IterateOverInterceptors(parts, f,
      _CHECK_FUNCTION, _CHECK_FUNCTION_NO_FLAGS, probe_index=probe_index,
      shadow_index=shadow_index)

  # Generate string operation accessors.
  probe_index = _IterateOverStringInterceptors(parts, f, _CHECK_STRINGS,
      probe_index=probe_index)

  # Close the custom segment housing the probges.
  parts.append(f.format(_INTERCEPTORS_SEGMENT_FOOTER))

  # Output the table of shadow references to .rdata.
  parts.append(f.format(_RDATA_SEGMENT_HEADER))
  parts.append(f.format(_SHADOW_REFERENCE_TABLE_HEADER))
  for i in range(0, shadow_index):
    parts.append(f.format(_SHADOW_REFERENCE_TABLE_ENTRY, shadow_index=i))
  parts.append(_SHADOW_REFERENCE_TABLE_FOOTER)
  parts.append(f.format(_RDATA_SEGMENT_FOOTER))

  parts.append(f.format(_ASM_TRAILER))

  return parts


def _GenerateRedirectorsAsmFile():
  f = MacroAssembler()
  parts = [f.format(_ASM_HEADER,
                    basename=os.path.basename(__file__),
                    year=datetime.datetime.now().year)]

  parts.append(f.format(_REDIRECTORS_EXTERN))

  # Declare the memory accessor redirectors.
  for suffix in ("", "_no_flags"):
    for access_size in _ACCESS_SIZES:
      for access, access_name in _ACCESS_MODES:
        parts.append(f.format(_REDIRECT_FUNCTION_DECL,
                              access_size=access_size,
                              access_mode_str=access,
                              access_mode_value=access_name,
                              suffix=suffix))

  # Declare string operation redirectors.
  for (fn, p, c, dst_mode, src_mode, size, compare) in _STRING_ACCESSORS:
    parts.append(f.format(_STRING_REDIRECT_FUNCTION_DECL,
                          func=fn,
                          prefix=p,
                          counter=c,
                          dst_mode=dst_mode,
                          src_mode=src_mode,
                          access_size=size,
                          compare=compare))

  parts.append(f.format(_REDIRECTORS_PROC_HEADER))

  # Generate the memory accessor redirectors.
  for suffix in ("", "_no_flags"):
    for access_size in _ACCESS_SIZES:
      for access, access_name in _ACCESS_MODES:
        parts.append(f.format(_REDIRECT_FUNCTION,
                              access_size=access_size,
                              access_mode_str=access,
                              access_mode_value=access_name,
                              suffix=suffix))

  # Generate string operation redirectors.
  for (fn, p, c, dst_mode, src_mode, size, compare) in _STRING_ACCESSORS:
    parts.append(f.format(_STRING_REDIRECT_FUNCTION,
                          func=fn,
                          prefix=p,
                          counter=c,
                          dst_mode=dst_mode,
                          src_mode=src_mode,
                          access_size=size,
                          compare=compare))

  parts.append(f.format(_REDIRECTORS_PROC_TRAILER))
  parts.append(f.format(_ASM_TRAILER))

  return parts


def _WriteFile(file_name, parts):
  contents = '\n'.join(parts)
  dir = os.path.dirname(__file__)
  with open(os.path.join(dir, file_name), "wb") as f:
    f.write(contents)


def main():
  interceptors_asm = _GenerateInterceptorsAsmFile()
  redirectors_asm = _GenerateRedirectorsAsmFile()

  _WriteFile('gen/memory_interceptors_impl.asm', interceptors_asm)
  _WriteFile('gen/memory_redirectors.asm', redirectors_asm)


if __name__ == '__main__':
  main()
