/*
 * Freestanding target-process payload.
 *
 * tools/build_logger_payload.py converts this object into a
 * position-independent .text image.  The payload has no writable globals and
 * no external imports.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "../common/protocol.h"

static __attribute__ ((always_inline)) inline uint64_t
logger_load_acquire_64 (const volatile uint64_t *address)
{
  return __atomic_load_n (address, __ATOMIC_ACQUIRE);
}

static __attribute__ ((always_inline)) inline void
logger_store_release_64 (volatile uint64_t *address, uint64_t value)
{
  __atomic_store_n (address, value, __ATOMIC_RELEASE);
}

__attribute__ ((naked, used, noinline)) bool
LoggerCompareExchange64 (volatile uint64_t *address, uint64_t expected,
                         uint64_t desired)
{
  /*
   * Windows x64 ABI: address=rcx, expected=rdx, desired=r8.
   * Return a zero-extended boolean in eax.
   */
  __asm__ volatile ("movq %rdx, %rax\n\t"
                    "lock cmpxchgq %r8, (%rcx)\n\t"
                    "sete %al\n\t"
                    "movzbl %al, %eax\n\t"
                    "ret\n\t");
}

static __attribute__ ((always_inline)) inline void
logger_send_record (const LOGGER_CONTEXT *context, uint32_t module_id,
                    uint32_t hook_rva, uint64_t caller_address,
                    uint32_t thread_id)
{
  volatile LOGGER_QUEUE_HEADER *queue;
  uint8_t *queue_base;
  uint64_t observed;
  uint64_t reserved;
  uint64_t offset;
  uint64_t tail;
  uint64_t available;
  LOGGER_LOG_RECORD *record;

  if (context == NULL || context->Magic != WIN_API_LOGGER_CONTEXT_MAGIC
      || context->Version != WIN_API_LOGGER_CLIENT_VERSION
      || context->QueueVa == 0
      || context->QueueSize != WIN_API_LOGGER_QUEUE_DATA_SIZE
      || context->QueueCapacity != WIN_API_LOGGER_QUEUE_CAPACITY)
    return;

  queue = (volatile LOGGER_QUEUE_HEADER *)(uintptr_t)context->QueueVa;
  queue_base = (uint8_t *)(uintptr_t)context->QueueVa;
  if (queue->Magic != WIN_API_LOGGER_QUEUE_MAGIC
      || queue->Capacity != WIN_API_LOGGER_QUEUE_DATA_SIZE
      || queue->RecordStride != WIN_API_LOGGER_LOG_RECORD_SIZE)
    return;

  for (;;)
    {
      observed = logger_load_acquire_64 (&queue->Head);
      if ((observed & 1u) != 0)
        continue;
      offset = observed >> 1;
  reserved = ((offset + WIN_API_LOGGER_LOG_RECORD_SIZE) << 1) | 1u;
      if (LoggerCompareExchange64 (&queue->Head, observed, reserved))
        break;
    }

  tail = logger_load_acquire_64 (&queue->Tail);
  available = offset >= tail ? offset - tail : 0;
  if (available + WIN_API_LOGGER_LOG_RECORD_SIZE
      > WIN_API_LOGGER_QUEUE_DATA_SIZE)
    {
      (void)__atomic_add_fetch (&queue->Dropped, 1, __ATOMIC_RELAXED);
      logger_store_release_64 (&queue->Head, offset << 1);
      return;
    }

  record = (LOGGER_LOG_RECORD *)(queue_base + WIN_API_LOGGER_QUEUE_HEADER_SIZE
                                 + (offset % WIN_API_LOGGER_QUEUE_DATA_SIZE));
  record->Length = (uint8_t)WIN_API_LOGGER_LOG_RECORD_SIZE;
  record->Version = (uint8_t)WIN_API_LOGGER_CLIENT_VERSION;
  record->Reserved = 0;
  record->ProcessId = context->ProcessId;
  record->ThreadId = thread_id;
  record->ModuleId = module_id;
  record->HookRva = hook_rva;
  record->Reserved2 = 0;
  record->CallerAddress = caller_address;

  __atomic_thread_fence (__ATOMIC_RELEASE);
  logger_store_release_64 (&queue->Head,
                           (offset + WIN_API_LOGGER_LOG_RECORD_SIZE) << 1);
}

__attribute__ ((used, visibility ("default"), noinline)) void
LoggerHandle (const LOGGER_CONTEXT *context, uint64_t module_id_rva,
              uint64_t caller_address, uint32_t thread_id)
{
  uint32_t module_id = (uint32_t)(module_id_rva >> 32);
  uint32_t hook_rva = (uint32_t)module_id_rva;

  if (context == NULL || context->Magic != WIN_API_LOGGER_CONTEXT_MAGIC)
    return;
  if (module_id >= WIN_API_LOGGER_MODULE_COUNT)
    return;
  logger_send_record (context, module_id, hook_rva, caller_address, thread_id);
}

/*
 * Stub stack layout at entry:
 *   [rsp + 0x00] return address to stub
 *   [rsp + 0x08] ModuleIdRva
 *   [rsp + 0x10] Context
 *   [rsp + 0x18] original caller return address
 *
 * After saving flags and all fifteen GPRs the values above are at rsp+0x80,
 * rsp+0x88, rsp+0x90, and rsp+0x98.  The payload never uses XMM registers.
 */
__attribute__ ((naked, used, visibility ("default"))) void
LoggerEntry (void)
{
  __asm__ volatile ("endbr64\n\t"
                    "pushfq\n\t"
                    "pushq %rax\n\t"
                    "pushq %rcx\n\t"
                    "pushq %rdx\n\t"
                    "pushq %rbx\n\t"
                    "pushq %rbp\n\t"
                    "pushq %rsi\n\t"
                    "pushq %rdi\n\t"
                    "pushq %r8\n\t"
                    "pushq %r9\n\t"
                    "pushq %r10\n\t"
                    "pushq %r11\n\t"
                    "pushq %r12\n\t"
                    "pushq %r13\n\t"
                    "pushq %r14\n\t"
                    "pushq %r15\n\t"
                    "movq 0x90(%rsp), %rcx\n\t"
                    "movq 0x88(%rsp), %rdx\n\t"
                    "movq 0x98(%rsp), %r8\n\t"
                    "movq %gs:0x48, %r9\n\t"
                    "subq $0x20, %rsp\n\t"
                    "callq LoggerHandle\n\t"
                    "addq $0x20, %rsp\n\t"
                    "popq %r15\n\t"
                    "popq %r14\n\t"
                    "popq %r13\n\t"
                    "popq %r12\n\t"
                    "popq %r11\n\t"
                    "popq %r10\n\t"
                    "popq %r9\n\t"
                    "popq %r8\n\t"
                    "popq %rdi\n\t"
                    "popq %rsi\n\t"
                    "popq %rbp\n\t"
                    "popq %rbx\n\t"
                    "popq %rdx\n\t"
                    "popq %rcx\n\t"
                    "popq %rax\n\t"
                    "popfq\n\t"
                    "retq\n\t"
                    "int3\n\t");
}
