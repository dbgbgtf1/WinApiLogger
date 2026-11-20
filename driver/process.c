#include <ntifs.h>

#include "state.h"

typedef BOOLEAN (NTAPI *LOGGER_PS_IS_PROTECTED) (_In_ PEPROCESS Process);

typedef struct _LOGGER_FILTER_ENTRY
{
  WCHAR Text[LOGGER_IMAGE_NAME_CHARS];
  USHORT Length;
} LOGGER_FILTER_ENTRY;

typedef struct _LOGGER_PENDING_IMAGE
{
  LIST_ENTRY ListEntry;
  HANDLE ProcessId;
  PVOID ImageBase;
  SIZE_T ImageSize;
  ULONG ModuleId;
} LOGGER_PENDING_IMAGE;

LIST_ENTRY g_ProcessStates;
KSPIN_LOCK g_ProcessStatesLock;

static LOGGER_FILTER_ENTRY g_Filters[WIN_API_LOGGER_MAX_FILTERS];
static KSPIN_LOCK g_FilterLock;
static LIST_ENTRY g_PendingImages;
static KSPIN_LOCK g_PendingImagesLock;
static ULONG g_FilterCount;
static volatile LONG64 g_NextStreamId;
static volatile LONG g_StateCount;
static BOOLEAN g_ProcessInitialized;
static LOGGER_PS_IS_PROTECTED g_PsIsProtectedProcess;
static LOGGER_PS_IS_PROTECTED g_PsIsProtectedProcessLight;

static NTSTATUS
LoggerResolveSystemRoutine (_In_ PCWSTR Name, _Out_ PVOID *Routine)
{
  UNICODE_STRING routine_name;

  *Routine = NULL;
  RtlInitUnicodeString (&routine_name, Name);
  *Routine = MmGetSystemRoutineAddress (&routine_name);
  if (*Routine == NULL)
    return STATUS_PROCEDURE_NOT_FOUND;
  return STATUS_SUCCESS;
}

static BOOLEAN
LoggerIsProtectedProcess (_In_ PEPROCESS Process)
{
  if (g_PsIsProtectedProcess != NULL && g_PsIsProtectedProcess (Process))
    return TRUE;
  if (g_PsIsProtectedProcessLight != NULL
      && g_PsIsProtectedProcessLight (Process))
    return TRUE;
  return FALSE;
}

static BOOLEAN
LoggerIsCriticalProcess (_In_ PEPROCESS Process)
{
  NTSTATUS status;
  HANDLE process_handle = NULL;
  ULONG break_on_termination = 0;
  ULONG returned_length = 0;

  status = ObOpenObjectByPointer (Process, OBJ_KERNEL_HANDLE, NULL,
                                  LOGGER_PROCESS_QUERY_LIMITED_INFORMATION,
                                  *PsProcessType, KernelMode, &process_handle);
  if (!NT_SUCCESS (status))
    return TRUE;

  status = ZwQueryInformationProcess (
      process_handle, ProcessBreakOnTermination, &break_on_termination,
      sizeof (break_on_termination), &returned_length);
  ZwClose (process_handle);
  if (!NT_SUCCESS (status))
    return TRUE;
  return break_on_termination != 0;
}

BOOLEAN
LoggerGetImageBaseName (_In_ PCUNICODE_STRING FullName,
                        _Out_writes_ (LOGGER_IMAGE_NAME_CHARS) PWCHAR BaseName,
                        _Out_ PUSHORT BaseNameChars)
{
  USHORT index;
  USHORT start = 0;

  *BaseNameChars = 0;
  BaseName[0] = UNICODE_NULL;
  if (FullName == NULL || FullName->Buffer == NULL || FullName->Length == 0)
    return FALSE;

  for (index = 0; index < FullName->Length / sizeof (WCHAR); ++index)
    {
      WCHAR character = FullName->Buffer[index];
      if (character == L'\\' || character == L'/')
        start = (USHORT)(index + 1);
    }
  if (start >= FullName->Length / sizeof (WCHAR))
    return FALSE;

  *BaseNameChars = (USHORT)(FullName->Length / sizeof (WCHAR) - start);
  if (*BaseNameChars == 0 || *BaseNameChars >= LOGGER_IMAGE_NAME_CHARS)
    return FALSE;
  RtlCopyMemory (BaseName, &FullName->Buffer[start],
                 *BaseNameChars * sizeof (WCHAR));
  BaseName[*BaseNameChars] = UNICODE_NULL;
  return TRUE;
}

ULONG
LoggerFindStaticModule (_In_ PCUNICODE_STRING BaseName)
{
  ULONG index;

  for (index = 0; index < LOGGER_MODULE_COUNT; ++index)
    {
      UNICODE_STRING candidate;
      RtlInitUnicodeString (&candidate, g_static_modules[index].base_name);
      if (RtlEqualUnicodeString (BaseName, &candidate, TRUE))
        return index;
    }
  return MAXULONG;
}

static BOOLEAN
LoggerFilterMatches (_In_ PCUNICODE_STRING BaseName)
{
  ULONG index;
  BOOLEAN matched = FALSE;
  KIRQL old_irql;

  KeAcquireSpinLock (&g_FilterLock, &old_irql);
  for (index = 0; index < g_FilterCount; ++index)
    {
      UNICODE_STRING candidate;
      candidate.Buffer = g_Filters[index].Text;
      candidate.Length = g_Filters[index].Length;
      candidate.MaximumLength = sizeof (g_Filters[index].Text);
      if (!RtlEqualUnicodeString (BaseName, &candidate, TRUE))
        continue;
      matched = TRUE;
      break;
    }
  KeReleaseSpinLock (&g_FilterLock, old_irql);
  return matched;
}

NTSTATUS
LoggerAddFilter (_In_ PCUNICODE_STRING BaseName)
{
  KIRQL old_irql;
  ULONG index;

  KeAcquireSpinLock (&g_FilterLock, &old_irql);
  for (index = 0; index < g_FilterCount; ++index)
    {
      UNICODE_STRING existing;
      existing.Buffer = g_Filters[index].Text;
      existing.Length = g_Filters[index].Length;
      existing.MaximumLength = sizeof (g_Filters[index].Text);
      if (!RtlEqualUnicodeString (&existing, BaseName, TRUE))
        continue;
      KeReleaseSpinLock (&g_FilterLock, old_irql);
      return STATUS_SUCCESS;
    }
  if (g_FilterCount >= WIN_API_LOGGER_MAX_FILTERS)
    {
      KeReleaseSpinLock (&g_FilterLock, old_irql);
      return STATUS_QUOTA_EXCEEDED;
    }
  RtlCopyMemory (g_Filters[g_FilterCount].Text, BaseName->Buffer,
                 BaseName->Length);
  g_Filters[g_FilterCount].Text[BaseName->Length / sizeof (WCHAR)]
      = UNICODE_NULL;
  g_Filters[g_FilterCount].Length = BaseName->Length;
  ++g_FilterCount;
  KeReleaseSpinLock (&g_FilterLock, old_irql);
  return STATUS_SUCCESS;
}

NTSTATUS
LoggerResetFilter (void)
{
  KIRQL old_irql;

  KeAcquireSpinLock (&g_FilterLock, &old_irql);
  g_FilterCount = 0;
  RtlZeroMemory (g_Filters, sizeof (g_Filters));
  KeReleaseSpinLock (&g_FilterLock, old_irql);
  return STATUS_SUCCESS;
}

NTSTATUS
LoggerProcessInitialize (void)
{
  if (g_ProcessInitialized)
    return STATUS_ALREADY_REGISTERED;

  InitializeListHead (&g_ProcessStates);
  InitializeListHead (&g_PendingImages);
  KeInitializeSpinLock (&g_ProcessStatesLock);
  KeInitializeSpinLock (&g_PendingImagesLock);
  KeInitializeSpinLock (&g_FilterLock);
  RtlZeroMemory (g_Filters, sizeof (g_Filters));
  g_FilterCount = 0;
  g_NextStreamId = 0;
  g_StateCount = 0;
  (void)LoggerResolveSystemRoutine (L"PsIsProtectedProcess",
                                    (PVOID *)&g_PsIsProtectedProcess);
  (void)LoggerResolveSystemRoutine (L"PsIsProtectedProcessLight",
                                    (PVOID *)&g_PsIsProtectedProcessLight);
  g_ProcessInitialized = TRUE;
  return STATUS_SUCCESS;
}

BOOLEAN
LoggerProcessHasLiveStates (void)
{
  if (!g_ProcessInitialized)
    return FALSE;
  return InterlockedCompareExchange (&g_StateCount, 0, 0) != 0;
}

static LOGGER_PROCESS_STATE *
LoggerFindStateByProcessLocked (_In_ PEPROCESS Process)
{
  PLIST_ENTRY entry;

  for (entry = g_ProcessStates.Flink; entry != &g_ProcessStates;
       entry = entry->Flink)
    {
      LOGGER_PROCESS_STATE *state
          = CONTAINING_RECORD (entry, LOGGER_PROCESS_STATE, ListEntry);
      if (state->Process != Process || state->DeletePending)
        continue;
      return state;
    }
  return NULL;
}

LOGGER_PROCESS_STATE *
LoggerFindStateByProcess (_In_ PEPROCESS Process)
{
  LOGGER_PROCESS_STATE *state;
  KIRQL old_irql;

  KeAcquireSpinLock (&g_ProcessStatesLock, &old_irql);
  state = LoggerFindStateByProcessLocked (Process);
  if (state != NULL)
    InterlockedIncrement (&state->ReferenceCount);
  KeReleaseSpinLock (&g_ProcessStatesLock, old_irql);
  return state;
}

LOGGER_PROCESS_STATE *
LoggerFindStateByStreamId (_In_ ULONGLONG StreamId)
{
  PLIST_ENTRY entry;
  LOGGER_PROCESS_STATE *state = NULL;
  KIRQL old_irql;

  KeAcquireSpinLock (&g_ProcessStatesLock, &old_irql);
  for (entry = g_ProcessStates.Flink; entry != &g_ProcessStates;
       entry = entry->Flink)
    {
      LOGGER_PROCESS_STATE *candidate
          = CONTAINING_RECORD (entry, LOGGER_PROCESS_STATE, ListEntry);
      if (candidate->DeletePending || candidate->StreamId != StreamId)
        continue;
      InterlockedIncrement (&candidate->ReferenceCount);
      state = candidate;
      break;
    }
  KeReleaseSpinLock (&g_ProcessStatesLock, old_irql);
  return state;
}

static VOID
LoggerFreeState (_In_ LOGGER_PROCESS_STATE *State)
{
  ULONG index;

  for (index = 0; index < WIN_API_LOGGER_MODULE_COUNT; ++index)
    {
      LOGGER_MODULE_STATE *module = &State->Modules[index];
      if (module->StubBase != NULL)
        LoggerFreeNearStub (State->Process, module->StubBase,
                            module->StubSize);
      if (module->ExportInstalled != NULL)
        {
          ExFreePoolWithTag (module->ExportInstalled, LOGGER_STATE_TAG);
          module->ExportInstalled = NULL;
        }
    }
  LoggerFreeLoggerView (State);
  LoggerFreePrivateData (State);
  ExDeleteResourceLite (&State->QueueResource);
  ExDeleteResourceLite (&State->InstallResource);
  if (State->Process != NULL)
    ObDereferenceObject (State->Process);
  InterlockedDecrement (&g_StateCount);
  ExFreePoolWithTag (State, LOGGER_STATE_TAG);
}

VOID
LoggerDereferenceState (_In_ LOGGER_PROCESS_STATE *State)
{
  if (InterlockedDecrement (&State->ReferenceCount) == 0)
    LoggerFreeState (State);
}

VOID
LoggerRememberPendingImage (_In_ HANDLE ProcessId, _In_ ULONG ModuleId,
                            _In_ PVOID ImageBase, _In_ SIZE_T ImageSize)
{
  LOGGER_PENDING_IMAGE *pending;
  PLIST_ENTRY entry;
  KIRQL old_irql;

  if (ModuleId >= WIN_API_LOGGER_MODULE_COUNT || ImageBase == NULL)
    return;
  pending = ExAllocatePool2 (POOL_FLAG_NON_PAGED, sizeof (*pending),
                             LOGGER_STATE_TAG);
  if (pending == NULL)
    return;
  pending->ProcessId = ProcessId;
  pending->ImageBase = ImageBase;
  pending->ImageSize = ImageSize;
  pending->ModuleId = ModuleId;

  KeAcquireSpinLock (&g_PendingImagesLock, &old_irql);
  for (entry = g_PendingImages.Flink; entry != &g_PendingImages;
       entry = entry->Flink)
    {
      LOGGER_PENDING_IMAGE *candidate
          = CONTAINING_RECORD (entry, LOGGER_PENDING_IMAGE, ListEntry);
      if (candidate->ProcessId == ProcessId
          && candidate->ModuleId == ModuleId)
        {
          KeReleaseSpinLock (&g_PendingImagesLock, old_irql);
          ExFreePoolWithTag (pending, LOGGER_STATE_TAG);
          return;
        }
    }
  InsertTailList (&g_PendingImages, &pending->ListEntry);
  KeReleaseSpinLock (&g_PendingImagesLock, old_irql);
}

static VOID
LoggerDiscardPendingImages (_In_ HANDLE ProcessId)
{
  LIST_ENTRY removed;
  PLIST_ENTRY entry;
  KIRQL old_irql;

  InitializeListHead (&removed);
  KeAcquireSpinLock (&g_PendingImagesLock, &old_irql);
  for (entry = g_PendingImages.Flink; entry != &g_PendingImages;)
    {
      LOGGER_PENDING_IMAGE *candidate
          = CONTAINING_RECORD (entry, LOGGER_PENDING_IMAGE, ListEntry);
      PLIST_ENTRY next = entry->Flink;
      if (ProcessId == NULL || candidate->ProcessId == ProcessId)
        {
          RemoveEntryList (&candidate->ListEntry);
          InsertTailList (&removed, &candidate->ListEntry);
        }
      entry = next;
    }
  KeReleaseSpinLock (&g_PendingImagesLock, old_irql);

  while (!IsListEmpty (&removed))
    {
      LOGGER_PENDING_IMAGE *candidate = CONTAINING_RECORD (
          RemoveHeadList (&removed), LOGGER_PENDING_IMAGE, ListEntry);
      ExFreePoolWithTag (candidate, LOGGER_STATE_TAG);
    }
}

static VOID
LoggerApplyPendingImages (_Inout_ LOGGER_PROCESS_STATE *State)
{
  LOGGER_PENDING_IMAGE *matches[WIN_API_LOGGER_MODULE_COUNT] = { NULL };
  ULONG match_count = 0;
  PLIST_ENTRY entry;
  KIRQL old_irql;
  ULONG index;

  KeAcquireSpinLock (&g_PendingImagesLock, &old_irql);
  for (entry = g_PendingImages.Flink; entry != &g_PendingImages;)
    {
      LOGGER_PENDING_IMAGE *candidate
          = CONTAINING_RECORD (entry, LOGGER_PENDING_IMAGE, ListEntry);
      PLIST_ENTRY next = entry->Flink;
      if (candidate->ProcessId == State->ProcessId)
        {
          RemoveEntryList (&candidate->ListEntry);
          if (match_count < WIN_API_LOGGER_MODULE_COUNT)
            matches[match_count++] = candidate;
          else
            ExFreePoolWithTag (candidate, LOGGER_STATE_TAG);
        }
      entry = next;
    }
  KeReleaseSpinLock (&g_PendingImagesLock, old_irql);

  if (match_count != 0)
    {
      ExAcquireResourceExclusiveLite (&State->InstallResource, TRUE);
      for (index = 0; index < match_count; ++index)
        {
          LOGGER_PENDING_IMAGE *pending = matches[index];
          if (!State->Exiting && State->Initialized
              && !State->Modules[pending->ModuleId].Loaded)
            (void)LoggerInstallModule (State, pending->ModuleId,
                                       pending->ImageBase,
                                       pending->ImageSize);
        }
      ExReleaseResourceLite (&State->InstallResource);
    }
  for (index = 0; index < match_count; ++index)
    ExFreePoolWithTag (matches[index], LOGGER_STATE_TAG);
}

VOID
LoggerRecordFailure (_Inout_ LOGGER_PROCESS_STATE *State, _In_ ULONG Reason)
{
  if (State->FailureReason == LoggerFailureNone)
    State->FailureReason = Reason;
}

VOID
LoggerRecordModuleFailure (_Inout_ LOGGER_PROCESS_STATE *State,
                           _In_ ULONG ModuleId, _In_ ULONG Reason)
{
  if (ModuleId >= WIN_API_LOGGER_MODULE_COUNT)
    return;
  State->Modules[ModuleId].FailureReason = Reason;
  LoggerRecordFailure (State, Reason);
}

static VOID
LoggerExitState (_Inout_ LOGGER_PROCESS_STATE *State)
{
  State->Exiting = TRUE;
  State->State = LoggerStreamExited;
}

static VOID
LoggerHandleProcessExit (_In_ PEPROCESS Process)
{
  LOGGER_PROCESS_STATE *state = LoggerFindStateByProcess (Process);
  KIRQL old_irql;

  if (state == NULL)
    return;
  ExAcquireResourceExclusiveLite (&state->InstallResource, TRUE);
  KeAcquireSpinLock (&g_ProcessStatesLock, &old_irql);
  if (!state->DeletePending)
    {
      RemoveEntryList (&state->ListEntry);
      InitializeListHead (&state->ListEntry);
      state->DeletePending = TRUE;
      LoggerExitState (state);
    }
  KeReleaseSpinLock (&g_ProcessStatesLock, old_irql);
  ExReleaseResourceLite (&state->InstallResource);
  LoggerDereferenceState (state);
  LoggerDereferenceState (state);
}

static LOGGER_PROCESS_STATE *
LoggerCreateState (_In_ PEPROCESS Process, _In_ HANDLE ProcessId,
                   _In_reads_ (ImageNameChars) const WCHAR *ImageName,
                   _In_ USHORT ImageNameChars)
{
  LOGGER_PROCESS_STATE *state;
  NTSTATUS status;

  state = ExAllocatePool2 (POOL_FLAG_NON_PAGED, sizeof (*state),
                           LOGGER_STATE_TAG);
  if (state == NULL)
    return NULL;
  RtlZeroMemory (state, sizeof (*state));
  InitializeListHead (&state->ListEntry);
  ExInitializeResourceLite (&state->InstallResource);
  ExInitializeResourceLite (&state->QueueResource);
  state->Process = Process;
  ObReferenceObject (Process);
  state->ProcessId = ProcessId;
  state->StreamId = (ULONGLONG)InterlockedIncrement64 (&g_NextStreamId);
  state->ImageNameChars = ImageNameChars;
  RtlCopyMemory (state->ImageName, ImageName,
                 (ImageNameChars + 1u) * sizeof (WCHAR));
  /*
   * The process list owns one reference until the exit callback removes the
   * entry.  Every cross-callback or IOCTL user acquires another reference.
   */
  state->ReferenceCount = 1;
  state->State = LoggerStreamInstalling;
  InterlockedIncrement (&g_StateCount);

  status = LoggerInitializePrivateData (state);
  if (!NT_SUCCESS (status))
    {
      state->FailureStatus = (ULONG)status;
      LoggerRecordFailure (state, LoggerFailurePrivateMappingFailed);
    }
  else
    {
      status = LoggerInitializeLoggerView (state);
      if (!NT_SUCCESS (status)
          && state->FailureReason == LoggerFailureNone)
        {
          state->FailureStatus = (ULONG)status;
          LoggerRecordFailure (state, LoggerFailureLoggerMappingFailed);
        }
    }
  if (NT_SUCCESS (status))
    status = LoggerInitializeQueue (state);
  if (!NT_SUCCESS (status))
    {
      if (state->FailureReason == LoggerFailureNone)
        {
          state->FailureStatus = (ULONG)status;
          LoggerRecordFailure (state,
                               LoggerFailureQueueInitializationFailed);
        }
      state->State = LoggerStreamFailed;
    }
  else
    state->State = LoggerStreamActive;
  state->Initialized = NT_SUCCESS (status);
  return state;
}

VOID
LoggerCreateProcessNotify (_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                           _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
  LOGGER_PROCESS_STATE *state;
  UNICODE_STRING base_name;
  WCHAR image_name[LOGGER_IMAGE_NAME_CHARS];
  USHORT image_name_chars;
  KIRQL old_irql;

  if (!g_ProcessInitialized)
    return;
  if (CreateInfo == NULL)
    {
      LoggerDiscardPendingImages (ProcessId);
      LoggerHandleProcessExit (Process);
      return;
    }
  if (CreateInfo->ImageFileName == NULL
      || !LoggerGetImageBaseName (CreateInfo->ImageFileName, image_name,
                                  &image_name_chars))
    {
      LoggerDiscardPendingImages (ProcessId);
      return;
    }

  base_name.Buffer = image_name;
  base_name.Length = image_name_chars * sizeof (WCHAR);
  base_name.MaximumLength = sizeof (image_name);
  if (!LoggerFilterMatches (&base_name))
    {
      LoggerDiscardPendingImages (ProcessId);
      return;
    }
  if (LoggerIsProtectedProcess (Process))
    {
      LoggerDiscardPendingImages (ProcessId);
      return;
    }
  if (LoggerIsCriticalProcess (Process))
    {
      LoggerDiscardPendingImages (ProcessId);
      return;
    }
  if (PsGetProcessWow64Process (Process) != NULL)
    {
      LoggerDiscardPendingImages (ProcessId);
      return;
    }

  state = LoggerCreateState (Process, ProcessId, image_name, image_name_chars);
  if (state == NULL)
    {
      LoggerDiscardPendingImages (ProcessId);
      return;
    }

  KeAcquireSpinLock (&g_ProcessStatesLock, &old_irql);
  InsertTailList (&g_ProcessStates, &state->ListEntry);
  KeReleaseSpinLock (&g_ProcessStatesLock, old_irql);
  LoggerInstallLoadedModules (state);
  LoggerApplyPendingImages (state);
}

VOID
LoggerProcessShutdown (void)
{
  if (!g_ProcessInitialized)
    return;
  LoggerResetFilter ();
  LoggerDiscardPendingImages (NULL);
  g_ProcessInitialized = FALSE;
}
