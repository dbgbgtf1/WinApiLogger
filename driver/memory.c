#include <ntifs.h>

#include "state.h"

LOGGER_SHARED_IMAGE g_LoggerImage;

static ULONG_PTR
LoggerAlignDown (_In_ ULONG_PTR Value, _In_ ULONG_PTR Alignment)
{
  return Value & ~(Alignment - 1u);
}

static ULONG_PTR
LoggerAlignUpPointer (_In_ ULONG_PTR Value, _In_ ULONG_PTR Alignment)
{
  return (Value + Alignment - 1u) & ~(Alignment - 1u);
}

NTSTATUS
LoggerMemoryInitialize (void)
{
  SIZE_T image_size;
  LARGE_INTEGER maximum_size;
  OBJECT_ATTRIBUTES attributes;
  NTSTATUS status;

  RtlZeroMemory (&g_LoggerImage, sizeof (g_LoggerImage));
  image_size = (LOGGER_PAYLOAD_SIZE + PAGE_SIZE - 1u) & ~(PAGE_SIZE - 1u);
  maximum_size.QuadPart = image_size;
  InitializeObjectAttributes (&attributes, NULL,
                              OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL,
                              NULL);
  status = ZwCreateSection (&g_LoggerImage.Section, SECTION_ALL_ACCESS,
                            &attributes, &maximum_size,
                            PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
  if (!NT_SUCCESS (status))
    {
      g_LoggerImage.Section = NULL;
      return status;
    }
  g_LoggerImage.Size = image_size;
  g_LoggerImage.MappingCount = 0;
  g_LoggerImage.Initialized = FALSE;
  KeInitializeMutex (&g_LoggerImage.InitializationMutex, 0);
  return STATUS_SUCCESS;
}

VOID
LoggerMemoryShutdown (void)
{
  if (g_LoggerImage.MappingCount != 0)
    return;
  if (g_LoggerImage.Section != NULL)
    {
      ZwClose (g_LoggerImage.Section);
      g_LoggerImage.Section = NULL;
    }
  g_LoggerImage.Size = 0;
  g_LoggerImage.Initialized = FALSE;
}

static VOID
LoggerFreeBufferMapping (_In_ PEPROCESS Process,
                         _Inout_ LOGGER_USER_BUFFER *Buffer)
{
  if (Buffer->Mapped && Buffer->UserVa != NULL && Buffer->Mdl != NULL)
    {
      KAPC_STATE apc_state;
      KeStackAttachProcess (Process, &apc_state);
      MmUnmapLockedPages (Buffer->UserVa, Buffer->Mdl);
      KeUnstackDetachProcess (&apc_state);
    }
  if (Buffer->Mdl != NULL)
    IoFreeMdl (Buffer->Mdl);
  if (Buffer->KernelVa != NULL)
    ExFreePoolWithTag (Buffer->KernelVa, LOGGER_MAPPING_TAG);
  RtlZeroMemory (Buffer, sizeof (*Buffer));
}

NTSTATUS
LoggerInitializePrivateData (_Inout_ LOGGER_PROCESS_STATE *State)
{
  KAPC_STATE apc_state;
  NTSTATUS status = STATUS_SUCCESS;
  PVOID user_va = NULL;
  PVOID kernel_va;
  PMDL mdl;

  kernel_va = ExAllocatePool2 (POOL_FLAG_NON_PAGED, LOGGER_PRIVATE_DATA_SIZE,
                               LOGGER_MAPPING_TAG);
  if (kernel_va == NULL)
    return STATUS_INSUFFICIENT_RESOURCES;
  RtlZeroMemory (kernel_va, LOGGER_PRIVATE_DATA_SIZE);
  mdl = IoAllocateMdl (kernel_va, (ULONG)LOGGER_PRIVATE_DATA_SIZE, FALSE,
                       FALSE, NULL);
  if (mdl == NULL)
    {
      ExFreePoolWithTag (kernel_va, LOGGER_MAPPING_TAG);
      return STATUS_INSUFFICIENT_RESOURCES;
    }
  MmBuildMdlForNonPagedPool (mdl);

  KeStackAttachProcess (State->Process, &apc_state);
  __try
    {
      user_va = MmMapLockedPagesSpecifyCache (
          mdl, UserMode, MmCached, NULL, FALSE,
          NormalPagePriority | MdlMappingNoExecute);
    }
  __except (LOGGER_HANDLE_MEMORY_EXCEPTION (GetExceptionCode ()))
    {
      status = GetExceptionCode ();
      user_va = NULL;
    }
  KeUnstackDetachProcess (&apc_state);
  if (user_va == NULL)
    {
      IoFreeMdl (mdl);
      ExFreePoolWithTag (kernel_va, LOGGER_MAPPING_TAG);
      return NT_SUCCESS (status) ? STATUS_INSUFFICIENT_RESOURCES : status;
    }

  State->Data.Mdl = mdl;
  State->Data.KernelVa = kernel_va;
  State->Data.UserVa = user_va;
  State->Data.Size = LOGGER_PRIVATE_DATA_SIZE;
  State->Data.Mapped = TRUE;
  State->Context = (LOGGER_CONTEXT *)kernel_va;
  State->QueueHeader = (LOGGER_QUEUE_HEADER *)((PUCHAR)kernel_va
                                               + LOGGER_QUEUE_HEADER_OFFSET);

  State->Context->Magic = WIN_API_LOGGER_CONTEXT_MAGIC;
  State->Context->Version = WIN_API_LOGGER_CLIENT_VERSION;
  State->Context->ProcessId = (UINT32)(ULONG_PTR)State->ProcessId;
  State->Context->QueueVa
      = (UINT64)(ULONG_PTR)((PUCHAR)user_va + LOGGER_QUEUE_HEADER_OFFSET);
  State->Context->QueueSize = WIN_API_LOGGER_QUEUE_DATA_SIZE;
  State->Context->QueueCapacity = WIN_API_LOGGER_QUEUE_CAPACITY;
  KeMemoryBarrier ();
  return STATUS_SUCCESS;
}

VOID
LoggerFreePrivateData (_Inout_ LOGGER_PROCESS_STATE *State)
{
  LoggerFreeBufferMapping (State->Process, &State->Data);
  State->Context = NULL;
  State->QueueHeader = NULL;
}

NTSTATUS
LoggerInitializeLoggerView (_Inout_ LOGGER_PROCESS_STATE *State)
{
  KAPC_STATE apc_state;
  NTSTATUS status = STATUS_SUCCESS;
  PVOID user_va = NULL;
  SIZE_T view_size;

  if (g_LoggerImage.Section == NULL || g_LoggerImage.Size == 0)
    return STATUS_INVALID_DEVICE_STATE;

  KeWaitForSingleObject (&g_LoggerImage.InitializationMutex, Executive,
                         KernelMode, FALSE, NULL);
  KeStackAttachProcess (State->Process, &apc_state);
  __try
    {
      if (!g_LoggerImage.Initialized)
        {
          view_size = g_LoggerImage.Size;
          status = ZwMapViewOfSection (
              g_LoggerImage.Section, NtCurrentProcess (), &user_va, 0, 0, NULL,
              &view_size, ViewShare, 0, PAGE_EXECUTE_READWRITE);
          if (NT_SUCCESS (status))
            {
              ProbeForWrite (user_va, LOGGER_PAYLOAD_SIZE, 1);
              RtlCopyMemory (user_va, g_logger_payload, LOGGER_PAYLOAD_SIZE);
              status = ZwUnmapViewOfSection (NtCurrentProcess (), user_va);
              user_va = NULL;
              if (NT_SUCCESS (status))
                g_LoggerImage.Initialized = TRUE;
            }
        }
      if (NT_SUCCESS (status))
        {
          view_size = g_LoggerImage.Size;
          status = ZwMapViewOfSection (
              g_LoggerImage.Section, NtCurrentProcess (), &user_va, 0, 0, NULL,
              &view_size, ViewShare, 0, PAGE_EXECUTE_READ);
          if (!NT_SUCCESS (status))
            user_va = NULL;
        }
    }
  __except (LOGGER_HANDLE_MEMORY_EXCEPTION (GetExceptionCode ()))
    {
      status = GetExceptionCode ();
      if (user_va != NULL)
        {
          (void)ZwUnmapViewOfSection (NtCurrentProcess (), user_va);
        }
      user_va = NULL;
    }
  KeUnstackDetachProcess (&apc_state);
  KeReleaseMutex (&g_LoggerImage.InitializationMutex, FALSE);
  if (!NT_SUCCESS (status) || user_va == NULL)
    {
      State->FailureStatus = (ULONG)(NT_SUCCESS (status)
                                         ? STATUS_INSUFFICIENT_RESOURCES
                                         : status);
      LoggerRecordFailure (State, LoggerFailureLoggerMappingFailed);
      return NT_SUCCESS (status) ? STATUS_INSUFFICIENT_RESOURCES : status;
    }

  State->LoggerVa = user_va;
  InterlockedIncrement (&g_LoggerImage.MappingCount);
  return STATUS_SUCCESS;
}

VOID
LoggerFreeLoggerView (_Inout_ LOGGER_PROCESS_STATE *State)
{
  KAPC_STATE apc_state;

  if (State->LoggerVa == NULL || g_LoggerImage.Section == NULL)
    return;
  KeStackAttachProcess (State->Process, &apc_state);
  (void)ZwUnmapViewOfSection (NtCurrentProcess (), State->LoggerVa);
  KeUnstackDetachProcess (&apc_state);
  State->LoggerVa = NULL;
  InterlockedDecrement (&g_LoggerImage.MappingCount);
}

static NTSTATUS
LoggerTryAllocateAt (_In_ PEPROCESS Process, _In_ ULONG_PTR Address,
                     _In_ SIZE_T Size, _Out_ PVOID *Allocated)
{
  KAPC_STATE apc_state;
  NTSTATUS status;
  PVOID base = (PVOID)Address;
  SIZE_T requested = Size;

  *Allocated = NULL;
  if (Address < 0x10000)
    return STATUS_INVALID_PARAMETER;
  KeStackAttachProcess (Process, &apc_state);
  status = ZwAllocateVirtualMemory (NtCurrentProcess (), &base, 0, &requested,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
  KeUnstackDetachProcess (&apc_state);
  if (!NT_SUCCESS (status))
    return status;
  if ((ULONG_PTR)base != Address || requested != Size)
    {
      PVOID unwanted = base;
      SIZE_T unwanted_size = 0;
      KeStackAttachProcess (Process, &apc_state);
      (void)ZwFreeVirtualMemory (NtCurrentProcess (), &unwanted,
                                 &unwanted_size, MEM_RELEASE);
      KeUnstackDetachProcess (&apc_state);
      return STATUS_CONFLICTING_ADDRESSES;
    }
  *Allocated = base;
  return STATUS_SUCCESS;
}

NTSTATUS
LoggerAllocateNearStub (_In_ PEPROCESS Process, _In_ PVOID ImageBase,
                        _In_ SIZE_T Size,
                        _In_opt_ LOGGER_NEAR_STUB_VALIDATOR Validator,
                        _In_opt_ PVOID Context, _Out_ PVOID *StubBase)
{
  ULONG_PTR base = (ULONG_PTR)ImageBase;
  ULONG_PTR rounded_size = (Size + 0xFFFFu) & ~0xFFFFULL;
  ULONG_PTR offset;
  NTSTATUS status = STATUS_ACCESS_DENIED;

  *StubBase = NULL;
  if (base < 0x10000 || rounded_size == 0 || rounded_size > Size + 0xFFFFu)
    return STATUS_INVALID_PARAMETER;

  for (offset = LOGGER_NEAR_STUB_START; offset <= LOGGER_NEAR_STUB_LIMIT;
       offset += LOGGER_NEAR_STUB_STEP)
    {
      ULONG_PTR lower;
      ULONG_PTR upper;

      if (base > offset + rounded_size)
        {
          lower = LoggerAlignDown (base - offset - rounded_size, 0x10000);
          status
              = LoggerTryAllocateAt (Process, lower, rounded_size, StubBase);
          if (NT_SUCCESS (status))
            {
              if (Validator == NULL || Validator (*StubBase, Context))
                return STATUS_SUCCESS;
              LoggerFreeNearStub (Process, *StubBase, rounded_size);
              *StubBase = NULL;
              status = STATUS_INTEGER_OVERFLOW;
            }
        }

      upper = LoggerAlignUpPointer (base + offset, 0x10000);
      status = LoggerTryAllocateAt (Process, upper, rounded_size, StubBase);
      if (NT_SUCCESS (status))
        {
          if (Validator == NULL || Validator (*StubBase, Context))
            return STATUS_SUCCESS;
          LoggerFreeNearStub (Process, *StubBase, rounded_size);
          *StubBase = NULL;
          status = STATUS_INTEGER_OVERFLOW;
        }
    }
  return status;
}

VOID
LoggerFreeNearStub (_In_ PEPROCESS Process, _In_ PVOID StubBase,
                    _In_ SIZE_T Size)
{
  KAPC_STATE apc_state;
  PVOID base = StubBase;
  SIZE_T region_size = 0;

  UNREFERENCED_PARAMETER (Size);
  if (StubBase == NULL)
    return;
  KeStackAttachProcess (Process, &apc_state);
  (void)ZwFreeVirtualMemory (NtCurrentProcess (), &base, &region_size,
                             MEM_RELEASE);
  KeUnstackDetachProcess (&apc_state);
}

NTSTATUS
LoggerWriteUserRange (_In_ PEPROCESS Process, _In_ PVOID Address,
                      _In_reads_bytes_ (Size) const VOID *Source,
                      _In_ SIZE_T Size)
{
  KAPC_STATE apc_state;
  NTSTATUS status = STATUS_SUCCESS;

  KeStackAttachProcess (Process, &apc_state);
  __try
    {
      ProbeForWrite (Address, Size, 1);
      RtlCopyMemory (Address, Source, Size);
    }
  __except (LOGGER_HANDLE_MEMORY_EXCEPTION (GetExceptionCode ()))
    {
      status = GetExceptionCode ();
    }
  KeUnstackDetachProcess (&apc_state);
  return status;
}

NTSTATUS
LoggerProtectUserCode (_In_ PEPROCESS Process, _In_ PVOID Address,
                       _In_ SIZE_T Size)
{
  KAPC_STATE apc_state;
  NTSTATUS status;
  PVOID base = Address;
  SIZE_T region_size = Size;
  ULONG old_protection = 0;

  KeStackAttachProcess (Process, &apc_state);
  status = ZwProtectVirtualMemory (NtCurrentProcess (), &base, &region_size,
                                   PAGE_EXECUTE_READ, &old_protection);
  KeUnstackDetachProcess (&apc_state);
  return status;
}

NTSTATUS
LoggerWriteTargetRange (_In_ PEPROCESS Process, _In_ PVOID Address,
                        _In_reads_bytes_opt_ (Size)
                            const VOID *ExpectedOriginal,
                        _In_reads_bytes_ (Size) const VOID *Replacement,
                        _In_ SIZE_T Size, _Out_opt_ PUCHAR Original,
                        _Out_opt_ PBOOLEAN BytesChanged)
{
  KAPC_STATE apc_state;
  NTSTATUS status;
  ULONG_PTR page_mask = PAGE_SIZE - 1u;
  ULONG_PTR protect_start = (ULONG_PTR)Address & ~page_mask;
  ULONG_PTR protect_end = ((ULONG_PTR)Address + Size + page_mask) & ~page_mask;
  PVOID base = (PVOID)protect_start;
  SIZE_T region_size = protect_end - protect_start;
  ULONG old_protection = 0;
  BOOLEAN protection_changed = FALSE;

  if (BytesChanged != NULL)
    *BytesChanged = FALSE;
  KeStackAttachProcess (Process, &apc_state);
  status = ZwProtectVirtualMemory (NtCurrentProcess (), &base, &region_size,
                                   PAGE_EXECUTE_READWRITE, &old_protection);
  protection_changed = NT_SUCCESS (status);
  if (NT_SUCCESS (status))
    {
      __try
        {
          ProbeForWrite (Address, Size, 1);
          if (Original != NULL)
            RtlCopyMemory (Original, Address, Size);
          if (ExpectedOriginal != NULL
              && !RtlEqualMemory (Address, ExpectedOriginal, Size))
            {
              KeMemoryBarrier ();
              YieldProcessor ();
              if (Original != NULL)
                RtlCopyMemory (Original, Address, Size);
              if (!RtlEqualMemory (Address, ExpectedOriginal, Size))
                status = STATUS_INVALID_IMAGE_HASH;
            }
          if (NT_SUCCESS (status))
            {
              if (BytesChanged != NULL)
                *BytesChanged = TRUE;
              RtlCopyMemory (Address, Replacement, Size);
            }
        }
      __except (LOGGER_HANDLE_MEMORY_EXCEPTION (GetExceptionCode ()))
        {
          status = GetExceptionCode ();
        }
    }
  if (protection_changed)
    {
      PVOID restore_base = (PVOID)protect_start;
      SIZE_T restore_size = protect_end - protect_start;
      ULONG ignored_protection = 0;
      NTSTATUS restore_status = ZwProtectVirtualMemory (
          NtCurrentProcess (), &restore_base, &restore_size, old_protection,
          &ignored_protection);
      if (NT_SUCCESS (status) && !NT_SUCCESS (restore_status))
        status = restore_status;
    }
  KeUnstackDetachProcess (&apc_state);
  return status;
}
