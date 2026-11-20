#include <ntifs.h>

#include "state.h"

NTSTATUS
LoggerInitializeQueue (_Inout_ LOGGER_PROCESS_STATE *State)
{
  PUCHAR data_base;

  if (State == NULL || State->Data.KernelVa == NULL || State->Context == NULL
      || State->QueueHeader == NULL)
    return STATUS_INVALID_PARAMETER;

  data_base = (PUCHAR)State->Data.KernelVa;
  RtlZeroMemory (State->QueueHeader, WIN_API_LOGGER_QUEUE_SIZE);
  State->QueueHeader->Tail = 0;
  State->QueueHeader->Dropped = 0;
  State->QueueHeader->Magic = WIN_API_LOGGER_QUEUE_MAGIC;
  State->QueueHeader->Capacity = WIN_API_LOGGER_QUEUE_DATA_SIZE;
  State->QueueHeader->RecordStride = WIN_API_LOGGER_LOG_RECORD_SIZE;
  State->Context->QueueSize = WIN_API_LOGGER_QUEUE_DATA_SIZE;
  State->Context->QueueCapacity = WIN_API_LOGGER_QUEUE_CAPACITY;
  KeMemoryBarrier ();
  State->QueueHeader->Head = 0;
  RtlZeroMemory (data_base + LOGGER_QUEUE_RECORDS_OFFSET,
                 WIN_API_LOGGER_QUEUE_DATA_SIZE);
  return STATUS_SUCCESS;
}

BOOLEAN
LoggerQueueHasRecords (_Inout_ LOGGER_PROCESS_STATE *State,
                       _In_ ULONG MaximumBytes)
{
  volatile LOGGER_QUEUE_HEADER *header;
  ULONG64 raw_head;
  ULONG64 committed;
  ULONG64 tail;
  ULONG available;

  if (State == NULL || State->QueueHeader == NULL
      || MaximumBytes < WIN_API_LOGGER_DRIVER_RECORD_SIZE)
    return FALSE;
  header = (volatile LOGGER_QUEUE_HEADER *)State->QueueHeader;
  if (header->Magic != WIN_API_LOGGER_QUEUE_MAGIC
      || header->Capacity != WIN_API_LOGGER_QUEUE_DATA_SIZE
      || header->RecordStride != WIN_API_LOGGER_LOG_RECORD_SIZE)
    return FALSE;

  raw_head
      = InterlockedCompareExchange64 ((volatile LONG64 *)&header->Head, 0, 0);
  committed = raw_head >> 1;
  if ((raw_head & 1u) != 0)
    {
      if (committed >= WIN_API_LOGGER_LOG_RECORD_SIZE)
        committed -= WIN_API_LOGGER_LOG_RECORD_SIZE;
      else
        committed = 0;
    }
  tail = InterlockedCompareExchange64 ((volatile LONG64 *)&header->Tail, 0, 0);
  if (committed < tail || committed - tail > WIN_API_LOGGER_QUEUE_DATA_SIZE)
    return FALSE;

  available = (ULONG)(committed - tail);
  return available >= WIN_API_LOGGER_LOG_RECORD_SIZE
         && MaximumBytes >= WIN_API_LOGGER_DRIVER_RECORD_SIZE;
}

static VOID
LoggerFillDriverRecord (_Out_ LOGGER_DRIVER_RECORD *Destination,
                        _In_ const LOGGER_LOG_RECORD *Source,
                        _In_ const LOGGER_MODULE_SNAPSHOT *Snapshot)
{
  const LOGGER_LOADED_MODULE *module;

  RtlZeroMemory (Destination, sizeof (*Destination));
  Destination->Length = (UINT8)WIN_API_LOGGER_DRIVER_RECORD_SIZE;
  Destination->Version = (UINT8)WIN_API_LOGGER_CLIENT_VERSION;
  Destination->ProcessId = Source->ProcessId;
  Destination->ThreadId = Source->ThreadId;
  Destination->ModuleId = Source->ModuleId;
  Destination->HookRva = Source->HookRva;
  Destination->CallerAddress = Source->CallerAddress;

  module = LoggerFindLoadedModule (Snapshot, (ULONG_PTR)Source->CallerAddress);
  if (module == NULL)
    return;
  Destination->CallerRva = (UINT32)((ULONG_PTR)Source->CallerAddress
                                    - module->ImageBase);
  while (Destination->CallerModuleChars
             < WIN_API_LOGGER_MODULE_NAME_CHARS - 1
         && module->BaseName[Destination->CallerModuleChars] != UNICODE_NULL)
    ++Destination->CallerModuleChars;
  RtlCopyMemory (Destination->CallerModule, module->BaseName,
                 Destination->CallerModuleChars * sizeof (WCHAR));
  Destination->CallerModule[Destination->CallerModuleChars] = UNICODE_NULL;
}

ULONG
LoggerReadQueue (_Inout_ LOGGER_PROCESS_STATE *State,
                 _In_ const LOGGER_MODULE_SNAPSHOT *Snapshot,
                 _Out_writes_bytes_ (MaximumBytes) PUCHAR Destination,
                 _In_ ULONG MaximumBytes)
{
  volatile LOGGER_QUEUE_HEADER *header;
  PUCHAR queue_base;
  ULONG64 raw_head;
  ULONG64 committed;
  ULONG64 tail;
  ULONG available;
  ULONG records;
  ULONG index;

  if (State == NULL || State->QueueHeader == NULL
      || State->Data.KernelVa == NULL || Destination == NULL)
    return 0;
  header = (volatile LOGGER_QUEUE_HEADER *)State->QueueHeader;
  if (header->Magic != WIN_API_LOGGER_QUEUE_MAGIC
      || header->Capacity != WIN_API_LOGGER_QUEUE_DATA_SIZE
      || header->RecordStride != WIN_API_LOGGER_LOG_RECORD_SIZE)
    return 0;

  raw_head
      = InterlockedCompareExchange64 ((volatile LONG64 *)&header->Head, 0, 0);
  committed = raw_head >> 1;
  if ((raw_head & 1u) != 0)
    {
      if (committed >= WIN_API_LOGGER_LOG_RECORD_SIZE)
        committed -= WIN_API_LOGGER_LOG_RECORD_SIZE;
      else
        committed = 0;
    }
  tail = InterlockedCompareExchange64 ((volatile LONG64 *)&header->Tail, 0, 0);
  if (committed < tail || committed - tail > WIN_API_LOGGER_QUEUE_DATA_SIZE)
    return 0;

  available = (ULONG)(committed - tail);
  records = MaximumBytes / WIN_API_LOGGER_DRIVER_RECORD_SIZE;
  if (records > available / WIN_API_LOGGER_LOG_RECORD_SIZE)
    records = available / WIN_API_LOGGER_LOG_RECORD_SIZE;
  if (records == 0)
    return 0;

  queue_base = (PUCHAR)State->Data.KernelVa + LOGGER_QUEUE_RECORDS_OFFSET;
  for (index = 0; index < records; ++index)
    {
      ULONG offset
          = (ULONG)((tail + (ULONG64)index * WIN_API_LOGGER_LOG_RECORD_SIZE)
                    % WIN_API_LOGGER_QUEUE_DATA_SIZE);
      LOGGER_LOG_RECORD source;

      RtlCopyMemory (&source, queue_base + offset, sizeof (source));
      LoggerFillDriverRecord (
          (LOGGER_DRIVER_RECORD *)(Destination
                                   + (SIZE_T)index
                                         * WIN_API_LOGGER_DRIVER_RECORD_SIZE),
          &source, Snapshot);
    }
  InterlockedExchange64 (
      (volatile LONG64 *)&header->Tail,
      (LONG64)(tail + (ULONG64)records * WIN_API_LOGGER_LOG_RECORD_SIZE));
  return records;
}
