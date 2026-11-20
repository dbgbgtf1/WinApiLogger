#include <ntifs.h>
#include <ntimage.h>

#include "state.h"
#include "../common/module_name.h"

static ULONG g_ExportStubOffset[LOGGER_INSTALLABLE_EXPORT_COUNT];
static ULONG g_ExportStubSize[LOGGER_INSTALLABLE_EXPORT_COUNT];
static ULONG g_ExportOrdinalInModule[LOGGER_INSTALLABLE_EXPORT_COUNT];
static ULONG g_ModuleExportCount[LOGGER_MODULE_COUNT];
static ULONG g_ModuleStubSize[LOGGER_MODULE_COUNT];

typedef struct _LOGGER_STUB_BUILD_FAILURE
{
  ULONG Reason;
  ULONG HookRva;
  UINT64 Source;
  UINT64 Destination;
  BOOLEAN Present;
} LOGGER_STUB_BUILD_FAILURE;

typedef struct _LOGGER_STUB_CANDIDATE_CONTEXT
{
  LOGGER_PROCESS_STATE *State;
  ULONG ModuleId;
  PUCHAR StubImage;
  LOGGER_STUB_BUILD_FAILURE Failure;
} LOGGER_STUB_CANDIDATE_CONTEXT;

typedef struct _LOGGER_PARTIAL_PEB
{
  UCHAR Reserved[0x18];
  PVOID Ldr;
} LOGGER_PARTIAL_PEB;

typedef struct _LOGGER_PARTIAL_PEB_LDR_DATA
{
  ULONG Length;
  BOOLEAN Initialized;
  UCHAR Padding[3];
  PVOID SsHandle;
  LIST_ENTRY InLoadOrderModuleList;
} LOGGER_PARTIAL_PEB_LDR_DATA;

typedef struct _LOGGER_LDR_DATA_TABLE_ENTRY
{
  LIST_ENTRY InLoadOrderLinks;
  LIST_ENTRY InMemoryOrderLinks;
  LIST_ENTRY InInitializationOrderLinks;
  PVOID DllBase;
  PVOID EntryPoint;
  ULONG SizeOfImage;
  ULONG Padding;
  UNICODE_STRING FullDllName;
  UNICODE_STRING BaseDllName;
} LOGGER_LDR_DATA_TABLE_ENTRY;

C_ASSERT (FIELD_OFFSET (LOGGER_PARTIAL_PEB, Ldr) == 0x18);
C_ASSERT (FIELD_OFFSET (LOGGER_PARTIAL_PEB_LDR_DATA,
                        InLoadOrderModuleList)
          == 0x10);
C_ASSERT (FIELD_OFFSET (LOGGER_LDR_DATA_TABLE_ENTRY, DllBase) == 0x30);
C_ASSERT (FIELD_OFFSET (LOGGER_LDR_DATA_TABLE_ENTRY, SizeOfImage) == 0x40);
C_ASSERT (FIELD_OFFSET (LOGGER_LDR_DATA_TABLE_ENTRY, FullDllName) == 0x48);
C_ASSERT (FIELD_OFFSET (LOGGER_LDR_DATA_TABLE_ENTRY, BaseDllName) == 0x58);

static BOOLEAN
LoggerCopyModuleStem (_In_ PCUNICODE_STRING Name,
                      _Out_writes_ (WIN_API_LOGGER_MODULE_NAME_CHARS)
                          PWCHAR Destination)
{
  if (Name == NULL || Name->Buffer == NULL || Name->Length == 0)
    {
      RtlZeroMemory (Destination,
                     WIN_API_LOGGER_MODULE_NAME_CHARS * sizeof (WCHAR));
      return FALSE;
    }
  return LoggerFormatModuleStem (Name->Buffer,
                                 Name->Length / sizeof (WCHAR),
                                 Destination)
         != 0;
}

NTSTATUS
LoggerBuildLoadedModuleSnapshot (
    _Inout_ LOGGER_PROCESS_STATE *State,
    _Inout_ LOGGER_MODULE_SNAPSHOT *Snapshot)
{
  KAPC_STATE apc_state;
  PPEB peb;
  LOGGER_PARTIAL_PEB *partial_peb;
  LOGGER_PARTIAL_PEB_LDR_DATA *loader;
  LIST_ENTRY *head;
  LIST_ENTRY *link;
  ULONG visited = 0;

  if (Snapshot == NULL)
    return STATUS_INVALID_PARAMETER;
  RtlZeroMemory (Snapshot, sizeof (*Snapshot));
  if (State == NULL || State->Exiting || !State->Initialized)
    return STATUS_SUCCESS;

  Snapshot->Entries = ExAllocatePool2 (
      POOL_FLAG_NON_PAGED,
      LOGGER_LOADED_MODULE_INITIAL_CAPACITY * sizeof (*Snapshot->Entries),
      LOGGER_STATE_TAG);
  if (Snapshot->Entries == NULL)
    return STATUS_INSUFFICIENT_RESOURCES;
  Snapshot->Capacity = LOGGER_LOADED_MODULE_INITIAL_CAPACITY;

  peb = PsGetProcessPeb (State->Process);
  if (peb == NULL)
    return STATUS_SUCCESS;

  KeStackAttachProcess (State->Process, &apc_state);
  __try
    {
      partial_peb = (LOGGER_PARTIAL_PEB *)peb;
      ProbeForRead (partial_peb, sizeof (*partial_peb), sizeof (ULONG_PTR));
      loader = (LOGGER_PARTIAL_PEB_LDR_DATA *)partial_peb->Ldr;
      if (loader == NULL)
        __leave;

      ProbeForRead (loader, sizeof (*loader), sizeof (ULONG_PTR));
      head = &loader->InLoadOrderModuleList;
      for (link = head->Flink;
           link != head && !State->Exiting && visited < LOGGER_LOADED_MODULE_LIMIT;
           ++visited)
        {
          LOGGER_LDR_DATA_TABLE_ENTRY *entry
              = (LOGGER_LDR_DATA_TABLE_ENTRY *)link;
          LOGGER_LOADED_MODULE *module;
          LOGGER_LOADED_MODULE *grown;
          ULONG new_capacity;
          ULONG_PTR image_base;

          ProbeForRead (entry, sizeof (*entry), sizeof (ULONG_PTR));
          link = entry->InLoadOrderLinks.Flink;
          if (entry->DllBase == NULL || entry->SizeOfImage == 0
              || entry->BaseDllName.Buffer == NULL
              || entry->BaseDllName.Length == 0
              || entry->BaseDllName.Length
                     > entry->BaseDllName.MaximumLength)
            continue;
          image_base = (ULONG_PTR)entry->DllBase;
          if (image_base > MAXULONG_PTR - entry->SizeOfImage)
            continue;

          ProbeForRead (entry->BaseDllName.Buffer,
                        entry->BaseDllName.Length, sizeof (WCHAR));
          if (Snapshot->Count == Snapshot->Capacity)
            {
              if (Snapshot->Capacity >= LOGGER_LOADED_MODULE_LIMIT)
                break;
              new_capacity = Snapshot->Capacity * 2;
              if (new_capacity > LOGGER_LOADED_MODULE_LIMIT)
                new_capacity = LOGGER_LOADED_MODULE_LIMIT;
              grown = ExAllocatePool2 (POOL_FLAG_NON_PAGED,
                                       new_capacity * sizeof (*grown),
                                       LOGGER_STATE_TAG);
              if (grown == NULL)
                break;
              RtlCopyMemory (grown, Snapshot->Entries,
                             Snapshot->Count * sizeof (*grown));
              ExFreePoolWithTag (Snapshot->Entries, LOGGER_STATE_TAG);
              Snapshot->Entries = grown;
              Snapshot->Capacity = new_capacity;
            }

          module = &Snapshot->Entries[Snapshot->Count];
          if (!LoggerCopyModuleStem (&entry->BaseDllName, module->BaseName))
            continue;
          module->ImageBase = image_base;
          module->SizeOfImage = entry->SizeOfImage;
          ++Snapshot->Count;
        }
    }
  __except (LOGGER_HANDLE_MEMORY_EXCEPTION (GetExceptionCode ()))
    {
      /* Caller resolution is best-effort and must not fail the stream. */
    }
  KeUnstackDetachProcess (&apc_state);
  return STATUS_SUCCESS;
}

VOID
LoggerFreeLoadedModuleSnapshot (_Inout_ LOGGER_MODULE_SNAPSHOT *Snapshot)
{
  if (Snapshot == NULL)
    return;
  if (Snapshot->Entries != NULL)
    ExFreePoolWithTag (Snapshot->Entries, LOGGER_STATE_TAG);
  RtlZeroMemory (Snapshot, sizeof (*Snapshot));
}

const LOGGER_LOADED_MODULE *
LoggerFindLoadedModule (_In_ const LOGGER_MODULE_SNAPSHOT *Snapshot,
                        _In_ ULONG_PTR Address)
{
  ULONG index;

  if (Snapshot == NULL || Address == 0)
    return NULL;
  for (index = 0; index < Snapshot->Count; ++index)
    {
      const LOGGER_LOADED_MODULE *module = &Snapshot->Entries[index];
      if (Address >= module->ImageBase
          && Address < module->ImageBase + module->SizeOfImage)
        return module;
    }
  return NULL;
}

static ULONG
LoggerAlignUp (_In_ ULONG Value, _In_ ULONG Alignment)
{
  return (Value + Alignment - 1u) & ~(Alignment - 1u);
}

NTSTATUS
LoggerInitializeStubLayout (void)
{
  ULONG module_id;
  ULONG index;

  RtlZeroMemory (g_ModuleExportCount, sizeof (g_ModuleExportCount));
  RtlZeroMemory (g_ModuleStubSize, sizeof (g_ModuleStubSize));
  for (index = 0; index < LOGGER_INSTALLABLE_EXPORT_COUNT; ++index)
    {
      const LOGGER_STATIC_EXPORT *item = &g_static_exports[index];
      ULONG module = item->module_id;
      ULONG module_index;
      ULONG size;

      if (module >= LOGGER_MODULE_COUNT
          || item->patch_length < LOGGER_ENTRY_PATCH_BYTES
          || item->patch_length > 15u
          || (item->rip_disp_offset != LOGGER_RIP_DISP_NONE
              && item->rip_disp_offset + sizeof (LONG) > item->patch_length)
          || item->hook_rva >= g_static_modules[module].size_of_image)
        return STATUS_INVALID_IMAGE_FORMAT;
      module_index = g_ModuleExportCount[module];
      size = LoggerAlignUp (LOGGER_STUB_FIXED_SIZE + item->patch_length, 16);
      g_ExportStubOffset[index]
          = LOGGER_STUB_HEADER_SIZE + g_ModuleStubSize[module];
      g_ExportStubSize[index] = size;
      g_ExportOrdinalInModule[index] = module_index;
      g_ModuleStubSize[module] += size;
      ++g_ModuleExportCount[module];
    }

  for (module_id = 0; module_id < LOGGER_MODULE_COUNT; ++module_id)
    g_ModuleStubSize[module_id]
        = LOGGER_STUB_HEADER_SIZE + g_ModuleStubSize[module_id];
  return STATUS_SUCCESS;
}

ULONG
LoggerExportStubOffset (_In_ ULONG ExportIndex)
{
  return g_ExportStubOffset[ExportIndex];
}

ULONG
LoggerExportStubSize (_In_ ULONG ExportIndex)
{
  return g_ExportStubSize[ExportIndex];
}

ULONG
LoggerModuleStubSize (_In_ ULONG ModuleId)
{
  return g_ModuleStubSize[ModuleId];
}

static BOOLEAN
LoggerIsCanonicalSystemPath (_In_ PCUNICODE_STRING FullImageName,
                             _In_ ULONG ModuleId)
{
  UNICODE_STRING expected;
  UNICODE_STRING system32_prefix;
  UNICODE_STRING base_name;
  UNICODE_STRING suffix;
  WCHAR suffix_buffer[LOGGER_IMAGE_NAME_CHARS + 16];
  USHORT prefix_chars;

  RtlInitUnicodeString (
      &expected, g_static_modules[ModuleId].canonical_image_name);
  if (RtlEqualUnicodeString (FullImageName, &expected, TRUE))
    return TRUE;

  RtlInitUnicodeString (&system32_prefix, L"\\System32\\");
  RtlInitUnicodeString (&base_name, g_static_modules[ModuleId].base_name);
  if ((system32_prefix.Length + base_name.Length) / sizeof (WCHAR)
      >= RTL_NUMBER_OF (suffix_buffer))
    return FALSE;
  RtlCopyMemory (suffix_buffer, system32_prefix.Buffer,
                 system32_prefix.Length);
  RtlCopyMemory ((PUCHAR)suffix_buffer + system32_prefix.Length,
                 base_name.Buffer, base_name.Length);
  suffix.Buffer = suffix_buffer;
  suffix.Length = system32_prefix.Length + base_name.Length;
  suffix.MaximumLength = suffix.Length + sizeof (WCHAR);
  suffix_buffer[suffix.Length / sizeof (WCHAR)] = UNICODE_NULL;
  if (FullImageName->Length <= suffix.Length)
    return FALSE;
  {
    UNICODE_STRING actual_suffix;
    USHORT suffix_chars = suffix.Length / sizeof (WCHAR);
    actual_suffix.Buffer
        = FullImageName->Buffer + FullImageName->Length / sizeof (WCHAR)
          - suffix_chars;
    actual_suffix.Length = suffix.Length;
    actual_suffix.MaximumLength = suffix.Length;
    if (!RtlEqualUnicodeString (&actual_suffix, &suffix, TRUE))
      return FALSE;
    prefix_chars = (FullImageName->Length - suffix.Length) / sizeof (WCHAR);
  }

  if (prefix_chars >= 12
      && RtlEqualMemory (FullImageName->Buffer, L"\\SystemRoot", 11
                                                            * sizeof (WCHAR))
             && FullImageName->Buffer[11] == L'\\')
    return TRUE;
  if (prefix_chars >= 4
      && RtlEqualMemory (FullImageName->Buffer, L"\\??\\", 4 * sizeof (WCHAR)))
    {
      WCHAR drive = FullImageName->Buffer[4];
      drive = (WCHAR)(drive & ~0x20);
      return prefix_chars > 6 && drive >= L'A' && drive <= L'Z'
             && FullImageName->Buffer[5] == L':'
             && FullImageName->Buffer[6] == L'\\';
    }
  if (prefix_chars >= 24
      && RtlEqualMemory (FullImageName->Buffer, L"\\Device\\HarddiskVolume",
                         22 * sizeof (WCHAR)))
    return TRUE;
  {
    WCHAR drive = (WCHAR)(FullImageName->Buffer[0] & ~0x20);
    return prefix_chars > 3 && drive >= L'A' && drive <= L'Z'
         && FullImageName->Buffer[1] == L':'
         && FullImageName->Buffer[2] == L'\\';
  }
}

VOID
LoggerInstallLoadedModules (_Inout_ LOGGER_PROCESS_STATE *State)
{
  KAPC_STATE apc_state;
  PPEB peb;
  LOGGER_PARTIAL_PEB *partial_peb;
  LOGGER_PARTIAL_PEB_LDR_DATA *loader;
  LIST_ENTRY *head;
  LIST_ENTRY *link;
  ULONG visited = 0;

  if (State == NULL || State->Exiting || !State->Initialized)
    return;
  peb = PsGetProcessPeb (State->Process);
  if (peb == NULL)
    return;

  ExAcquireResourceExclusiveLite (&State->InstallResource, TRUE);
  KeStackAttachProcess (State->Process, &apc_state);
  __try
    {
      partial_peb = (LOGGER_PARTIAL_PEB *)peb;
      ProbeForRead (partial_peb, sizeof (*partial_peb), sizeof (ULONG_PTR));
      loader = (LOGGER_PARTIAL_PEB_LDR_DATA *)partial_peb->Ldr;
      if (loader != NULL)
        {
          ProbeForRead (loader, sizeof (*loader), sizeof (ULONG_PTR));
          head = &loader->InLoadOrderModuleList;
          for (link = head->Flink;
               link != head && !State->Exiting && visited < 256; ++visited)
            {
              LOGGER_LDR_DATA_TABLE_ENTRY *entry
                  = (LOGGER_LDR_DATA_TABLE_ENTRY *)link;
              ULONG module_id;

              ProbeForRead (entry, sizeof (*entry), sizeof (ULONG_PTR));
              link = entry->InLoadOrderLinks.Flink;
              if (entry->DllBase == NULL || entry->SizeOfImage == 0
                  || entry->BaseDllName.Buffer == NULL
                  || entry->BaseDllName.Length == 0
                  || entry->BaseDllName.Length
                         > entry->BaseDllName.MaximumLength)
                continue;
              ProbeForRead (entry->BaseDllName.Buffer,
                            entry->BaseDllName.Length, sizeof (WCHAR));
              module_id = LoggerFindStaticModule (&entry->BaseDllName);
              if (module_id >= LOGGER_MODULE_COUNT
                  || State->Modules[module_id].Loaded)
                continue;
              if (entry->FullDllName.Buffer != NULL
                  && entry->FullDllName.Length != 0
                  && entry->FullDllName.Length
                         <= entry->FullDllName.MaximumLength)
                {
                  ProbeForRead (entry->FullDllName.Buffer,
                                entry->FullDllName.Length, sizeof (WCHAR));
                  if (!LoggerIsCanonicalSystemPath (&entry->FullDllName,
                                                    module_id))
                    continue;
                }
              (void)LoggerInstallModule (State, module_id, entry->DllBase,
                                         entry->SizeOfImage);
            }
        }
    }
  __except (LOGGER_HANDLE_MEMORY_EXCEPTION (GetExceptionCode ()))
    {
      State->FailureStatus = (ULONG)GetExceptionCode ();
      LoggerRecordFailure (State, LoggerFailureInvalidState);
    }
  KeUnstackDetachProcess (&apc_state);
  ExReleaseResourceLite (&State->InstallResource);
}

static BOOLEAN
LoggerCanEncodeRel32 (_In_ const VOID *Source, _In_ const VOID *Destination,
                      _Out_ LONG *Displacement)
{
  ULONG_PTR source = (ULONG_PTR)Source;
  ULONG_PTR next;
  ULONG_PTR destination = (ULONG_PTR)Destination;

  *Displacement = 0;
  if (source > MAXULONG_PTR - LOGGER_ENTRY_PATCH_BYTES)
    return FALSE;
  next = source + LOGGER_ENTRY_PATCH_BYTES;
  if (destination >= next)
    {
      ULONGLONG distance = (ULONGLONG)(destination - next);
      if (distance > MAXLONG)
        return FALSE;
      *Displacement = (LONG)distance;
      return TRUE;
    }

  if (next - destination > 0x80000000ULL)
    return FALSE;
  *Displacement = (LONG)(-(LONG64)(next - destination));
  return TRUE;
}

static NTSTATUS
LoggerRollbackModule (_Inout_ LOGGER_PROCESS_STATE *State, _In_ ULONG ModuleId,
                      _In_ ULONG InstalledCount)
{
  NTSTATUS status = STATUS_SUCCESS;
  LOGGER_MODULE_STATE *module = &State->Modules[ModuleId];
  ULONG index;

  for (index = 0; index < LOGGER_INSTALLABLE_EXPORT_COUNT; ++index)
    {
      const LOGGER_STATIC_EXPORT *item = &g_static_exports[index];
      NTSTATUS current;
      PVOID target;

      if (item->module_id != ModuleId
          || !module->ExportInstalled[g_ExportOrdinalInModule[index]])
        continue;
      target = (PUCHAR)(ULONG_PTR)module->ImageBase + item->hook_rva;
      current = LoggerWriteTargetRange (State->Process, target, NULL,
                                        item->original_bytes,
                                        item->patch_length, NULL, NULL);
      if (!NT_SUCCESS (current))
        {
          status = STATUS_UNSUCCESSFUL;
          continue;
        }
      module->ExportInstalled[g_ExportOrdinalInModule[index]] = 0;
      --InstalledCount;
    }

  if (!NT_SUCCESS (status))
    {
      State->State = LoggerStreamFailed;
      LoggerRecordModuleFailure (State, ModuleId, LoggerFailureRollbackFailed);
      return status;
    }

  if (module->StubBase != NULL)
    {
      LoggerFreeNearStub (State->Process, module->StubBase, module->StubSize);
      module->StubBase = NULL;
      module->StubSize = 0;
    }
  module->StubProtected = FALSE;
  return STATUS_SUCCESS;
}

static BOOLEAN
LoggerBuildModuleStubs (_Inout_ LOGGER_PROCESS_STATE *State,
                        _In_ ULONG ModuleId,
                        _Out_writes_bytes_ (State->Modules[ModuleId].StubSize)
                            PUCHAR StubImage,
                        _In_ PVOID CandidateBase,
                        _Out_ LOGGER_STUB_BUILD_FAILURE *Failure)
{
  LOGGER_MODULE_STATE *module = &State->Modules[ModuleId];
  PUCHAR stub_base = StubImage;
  ULONG_PTR logger_entry
      = (ULONG_PTR)State->LoggerVa + LOGGER_PAYLOAD_ENTRY_RVA;
  ULONG index;

  RtlZeroMemory (Failure, sizeof (*Failure));

  // Common slots at the start of each module stub region.
  // qword ContextSlot
  // qword LoggerEntrySlot
  RtlZeroMemory (stub_base, module->StubSize);
  *((ULONG_PTR *)(stub_base + 0))
      = (ULONG_PTR)State->Data.UserVa + LOGGER_CONTEXT_OFFSET;
  *((ULONG_PTR *)(stub_base + 8)) = logger_entry;

  for (index = 0; index < LOGGER_INSTALLABLE_EXPORT_COUNT; ++index)
    {
      const LOGGER_STATIC_EXPORT *item = &g_static_exports[index];
      ULONG offset;
      ULONG size;
      ULONG module_id_rva_in_stub;
      ULONG module_id_rva_offset;
      LONG displacement;
      PUCHAR stub;

      if (item->module_id != ModuleId)
        continue;
      offset = g_ExportStubOffset[index];
      size = g_ExportStubSize[index];
      module_id_rva_in_stub
          = LOGGER_STUB_ORIGINAL_OFFSET + LOGGER_ENTRY_PATCH_BYTES
            + (ULONG)item->patch_length;
      module_id_rva_offset = offset + module_id_rva_in_stub;
      stub = stub_base + offset;

      // F3 0F 1E FA                      ; endbr64
      // FF 35 <ContextSlot disp32>       ; push qword ptr [rip + ContextSlot]
      stub[0] = 0xF3;
      stub[1] = 0x0F;
      stub[2] = 0x1E;
      stub[3] = 0xFA;
      stub[4] = 0xFF;
      stub[5] = 0x35;
      displacement = (LONG)(0u - (offset + 10u));
      RtlCopyMemory (stub + 6, &displacement, sizeof (displacement));

      // FF 35 <ModuleIdRvaSlot disp32>   ; push qword ptr [rip +
      // ModuleIdRvaSlot]
      stub[10] = 0xFF;
      stub[11] = 0x35;
      displacement = (LONG)(module_id_rva_offset - (offset + 16u));
      RtlCopyMemory (stub + 12, &displacement, sizeof (displacement));

      // FF 15 <LoggerEntrySlot disp32>   ; call qword ptr [rip +
      // LoggerEntrySlot]
      stub[16] = 0xFF;
      stub[17] = 0x15;
      displacement = (LONG)(8u - (offset + 22u));
      RtlCopyMemory (stub + 18, &displacement, sizeof (displacement));

      // 48 8D 64 24 10                   ; lea rsp, [rsp + 0x10]
      stub[22] = 0x48;
      stub[23] = 0x8D;
      stub[24] = 0x64;
      stub[25] = 0x24;
      stub[26] = 0x10;

      // <patch_length bytes>             ; copy complete original prologue
      RtlCopyMemory (stub + LOGGER_STUB_ORIGINAL_OFFSET, item->original_bytes,
                     item->patch_length);

      if (item->rip_disp_offset != LOGGER_RIP_DISP_NONE)
        {
          LONG old_displacement;
          LONG new_displacement;
          INT64 delta;
          INT64 adjusted;
          PUCHAR copied_instruction
              = stub + LOGGER_STUB_ORIGINAL_OFFSET;
          PUCHAR final_instruction
              = (PUCHAR)CandidateBase + offset + LOGGER_STUB_ORIGINAL_OFFSET;
          PUCHAR original_entry
              = (PUCHAR)(ULONG_PTR)module->ImageBase + item->hook_rva;

          if ((ULONG)item->rip_disp_offset + sizeof (old_displacement)
              > item->patch_length)
            {
              Failure->Reason = LoggerFailureRipRelocationFailed;
              Failure->HookRva = item->hook_rva;
              Failure->Source = (UINT64)(ULONG_PTR)final_instruction;
              Failure->Destination
                  = (UINT64)(ULONG_PTR)original_entry
                    + (UINT64)(LONG64)item->rip_target_rva;
              Failure->Present = TRUE;
              return FALSE;
            }

          RtlCopyMemory (&old_displacement,
                         copied_instruction + item->rip_disp_offset,
                         sizeof (old_displacement));
          delta = (INT64)(ULONG_PTR)final_instruction
                  - (INT64)(ULONG_PTR)original_entry;
          adjusted = (INT64)old_displacement - delta;
          if (adjusted < -(INT64)MAXLONG - 1 || adjusted > (INT64)MAXLONG)
            {
              Failure->Reason = LoggerFailureRipRelocationFailed;
              Failure->HookRva = item->hook_rva;
              Failure->Source
                  = (UINT64)(ULONG_PTR)(final_instruction
                                        + item->rip_disp_offset);
              Failure->Destination
                  = (UINT64)(ULONG_PTR)original_entry
                    + (UINT64)(LONG64)item->rip_target_rva;
              Failure->Present = TRUE;
              return FALSE;
            }
          new_displacement = (LONG)adjusted;
          RtlCopyMemory (copied_instruction + item->rip_disp_offset,
                         &new_displacement, sizeof (new_displacement));
        }

      // E9 <continuation rel32>          ; jump to original + patch_length
      stub[LOGGER_STUB_ORIGINAL_OFFSET + item->patch_length] = 0xE9;
      {
        PVOID continuation = (PUCHAR)(ULONG_PTR)module->ImageBase
                             + item->hook_rva + item->patch_length;
        PUCHAR final_stub = (PUCHAR)CandidateBase + offset;
        if (!LoggerCanEncodeRel32 (
                final_stub + LOGGER_STUB_ORIGINAL_OFFSET + item->patch_length,
                continuation, &displacement))
          {
            Failure->Reason = LoggerFailureInvalidModuleIdRva;
            Failure->HookRva = item->hook_rva;
            Failure->Source
                = (UINT64)(ULONG_PTR)(final_stub
                                      + LOGGER_STUB_ORIGINAL_OFFSET
                                      + item->patch_length);
            Failure->Destination = (UINT64)(ULONG_PTR)continuation;
            Failure->Present = TRUE;
            return FALSE;
          }
      }

      // <qword ModuleIdRva>              ; ModuleId << 32 | HookRva
      RtlCopyMemory (stub + LOGGER_STUB_ORIGINAL_OFFSET + 1
                         + item->patch_length,
                     &displacement,
                     sizeof (displacement));
      *((ULONG64 *)(stub + module_id_rva_in_stub))
          = ((ULONG64)ModuleId << 32) | item->hook_rva;

      // CC ...                           ; pad to 16-byte alignment
      RtlFillMemory (stub + module_id_rva_in_stub + sizeof (ULONG64),
                     size - module_id_rva_in_stub - sizeof (ULONG64), 0xCC);
    }
  return TRUE;
}

static BOOLEAN
LoggerBuildStubCandidate (_In_ PVOID CandidateBase, _In_ PVOID Context)
{
  LOGGER_STUB_CANDIDATE_CONTEXT *context
      = (LOGGER_STUB_CANDIDATE_CONTEXT *)Context;

  return LoggerBuildModuleStubs (context->State, context->ModuleId,
                                 context->StubImage, CandidateBase,
                                 &context->Failure);
}

static NTSTATUS
LoggerPatchModule (_Inout_ LOGGER_PROCESS_STATE *State, _In_ ULONG ModuleId)
{
  LOGGER_MODULE_STATE *module = &State->Modules[ModuleId];
  ULONG index;

  for (index = 0; index < LOGGER_INSTALLABLE_EXPORT_COUNT; ++index)
    {
      const LOGGER_STATIC_EXPORT *item = &g_static_exports[index];
      UCHAR patch[15];
      UCHAR actual[15];
      ULONG ordinal = g_ExportOrdinalInModule[index];
      PVOID target;
      PVOID stub;
      LONG displacement;
      NTSTATUS status;
      BOOLEAN changed;

      if (item->module_id != ModuleId || module->ExportInstalled[ordinal])
        continue;
      target = (PUCHAR)(ULONG_PTR)module->ImageBase + item->hook_rva;
      stub = (PUCHAR)module->StubBase + g_ExportStubOffset[index];
      if (!LoggerCanEncodeRel32 (target, stub, &displacement))
        return STATUS_INTEGER_OVERFLOW;

      RtlZeroMemory (patch, sizeof (patch));
      patch[0] = 0xE9;
      RtlCopyMemory (patch + 1, &displacement, sizeof (displacement));
      RtlFillMemory (patch + LOGGER_ENTRY_PATCH_BYTES,
                     item->patch_length - LOGGER_ENTRY_PATCH_BYTES, 0x90);
      RtlZeroMemory (actual, sizeof (actual));
      changed = FALSE;
      status = LoggerWriteTargetRange (State->Process, target,
                                       item->original_bytes, patch,
                                       item->patch_length, actual, &changed);
      if (!NT_SUCCESS (status))
        {
          if (changed)
            module->ExportInstalled[ordinal] = 1;
          if (status == STATUS_INVALID_IMAGE_HASH)
            {
              State->FailureStatus = item->hook_rva;
              State->FailureSource = (UINT64)(ULONG_PTR)target;
              RtlCopyMemory (&State->FailureDestination,
                             actual, sizeof (UINT32) * 2);
              return STATUS_INVALID_IMAGE_HASH;
            }
          return STATUS_UNSUCCESSFUL;
        }
      module->ExportInstalled[ordinal] = 1;
    }
  return STATUS_SUCCESS;
}

NTSTATUS
LoggerInstallModule (_Inout_ LOGGER_PROCESS_STATE *State, _In_ ULONG ModuleId,
                     _In_ PVOID ImageBase, _In_ SIZE_T ImageSize)
{
  LOGGER_MODULE_STATE *module = &State->Modules[ModuleId];
  PUCHAR stub_image = NULL;
  NTSTATUS status;
  ULONG installed_count = 0;
  ULONG index;
  LOGGER_STUB_CANDIDATE_CONTEXT candidate_context;

  if (ImageSize != 0 && ImageSize != g_static_modules[ModuleId].size_of_image)
    {
      LoggerRecordModuleFailure (State, ModuleId, LoggerFailureModuleMismatch);
      return STATUS_INVALID_IMAGE_HASH;
    }
  status = LoggerValidateLoadedModule (State->Process, ModuleId, ImageBase);
  if (!NT_SUCCESS (status))
    {
      LoggerRecordModuleFailure (State, ModuleId, LoggerFailureModuleMismatch);
      return status;
    }

  module->Loaded = TRUE;
  module->ImageBase = (ULONG64)(ULONG_PTR)ImageBase;
  module->ImageSize = ImageSize != 0
                          ? (UINT32)ImageSize
                          : g_static_modules[ModuleId].size_of_image;
  if (module->ExportInstalled == NULL)
    {
      ULONG count = g_ModuleExportCount[ModuleId];
      module->ExportInstalled
          = ExAllocatePool2 (POOL_FLAG_NON_PAGED, count, LOGGER_STATE_TAG);
      if (module->ExportInstalled == NULL)
        {
          LoggerRecordModuleFailure (State, ModuleId,
                                     LoggerFailureOutOfMemory);
          return STATUS_INSUFFICIENT_RESOURCES;
        }
      RtlZeroMemory (module->ExportInstalled, count);
    }

  module->StubSize = LoggerModuleStubSize (ModuleId);
  stub_image = ExAllocatePool2 (POOL_FLAG_NON_PAGED, module->StubSize,
                                LOGGER_MAPPING_TAG);
  if (stub_image == NULL)
    {
      LoggerRecordModuleFailure (State, ModuleId, LoggerFailureOutOfMemory);
      return STATUS_INSUFFICIENT_RESOURCES;
    }
  RtlZeroMemory (&candidate_context, sizeof (candidate_context));
  candidate_context.State = State;
  candidate_context.ModuleId = ModuleId;
  candidate_context.StubImage = stub_image;
  status = LoggerAllocateNearStub (State->Process, ImageBase, module->StubSize,
                                   LoggerBuildStubCandidate,
                                   &candidate_context, &module->StubBase);
  if (!NT_SUCCESS (status))
    {
      ExFreePoolWithTag (stub_image, LOGGER_MAPPING_TAG);
      module->StubBase = NULL;
      if (candidate_context.Failure.Present)
        {
          State->FailureStatus = candidate_context.Failure.HookRva;
          State->FailureSource = candidate_context.Failure.Source;
          State->FailureDestination = candidate_context.Failure.Destination;
          LoggerRecordModuleFailure (State, ModuleId,
                                     candidate_context.Failure.Reason);
        }
      else
        {
          LoggerRecordModuleFailure (State, ModuleId,
                                     LoggerFailureStubAllocationFailed);
        }
      return status;
    }
  status = LoggerWriteUserRange (State->Process, module->StubBase, stub_image,
                                 module->StubSize);
  ExFreePoolWithTag (stub_image, LOGGER_MAPPING_TAG);
  if (!NT_SUCCESS (status))
    {
      LoggerFreeNearStub (State->Process, module->StubBase, module->StubSize);
      module->StubBase = NULL;
      LoggerRecordModuleFailure (State, ModuleId,
                                 LoggerFailureStubAllocationFailed);
      return status;
    }

  status = LoggerProtectUserCode (State->Process, module->StubBase,
                                  module->StubSize);
  if (!NT_SUCCESS (status))
    {
      LoggerFreeNearStub (State->Process, module->StubBase, module->StubSize);
      module->StubBase = NULL;
      LoggerRecordModuleFailure (State, ModuleId,
                                 LoggerFailureStubProtectionFailed);
      return status;
    }
  module->StubProtected = TRUE;

  status = LoggerPatchModule (State, ModuleId);
  if (NT_SUCCESS (status))
    return STATUS_SUCCESS;

  for (index = 0; index < g_ModuleExportCount[ModuleId]; ++index)
    installed_count += module->ExportInstalled[index] != 0;
  LoggerRecordModuleFailure (
      State, ModuleId,
      status == STATUS_INVALID_IMAGE_HASH ? LoggerFailurePatchMismatch
      : status == STATUS_INTEGER_OVERFLOW
          ? LoggerFailureInvalidModuleIdRva
                                          : LoggerFailurePatchFailed);
  (void)LoggerRollbackModule (State, ModuleId, installed_count);
  return status;
}

VOID
LoggerLoadImageNotify (_In_opt_ PUNICODE_STRING FullImageName,
                       _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo)
{
  ULONG module_id;
  PEPROCESS process;
  LOGGER_PROCESS_STATE *state;
  NTSTATUS status;

  if (FullImageName == NULL || ImageInfo == NULL || ImageInfo->SystemModeImage
      || ImageInfo->ImageAddressingMode == IMAGE_ADDRESSING_MODE_32BIT
      || ImageInfo->ImagePartialMap)
    return;

  {
    WCHAR image_name[LOGGER_IMAGE_NAME_CHARS];
    USHORT image_name_chars;
    UNICODE_STRING base_name;
    if (!LoggerGetImageBaseName (FullImageName, image_name, &image_name_chars))
      return;
    base_name.Buffer = image_name;
    base_name.Length = image_name_chars * sizeof (WCHAR);
    base_name.MaximumLength = sizeof (image_name);
    module_id = LoggerFindStaticModule (&base_name);
  }

  if (module_id == MAXULONG
      || !LoggerIsCanonicalSystemPath (FullImageName, module_id))
    return;

  status = PsLookupProcessByProcessId (ProcessId, &process);
  if (!NT_SUCCESS (status))
    return;
  state = LoggerFindStateByProcess (process);
  ObDereferenceObject (process);
  if (state == NULL)
    {
      LoggerRememberPendingImage (ProcessId, module_id, ImageInfo->ImageBase,
                                  ImageInfo->ImageSize);
      return;
    }

  ExAcquireResourceExclusiveLite (&state->InstallResource, TRUE);
  if (!state->Exiting && state->Initialized
      && state->Modules[module_id].Loaded == FALSE)
    (void)LoggerInstallModule (state, module_id, ImageInfo->ImageBase,
                               ImageInfo->ImageSize);
  ExReleaseResourceLite (&state->InstallResource);
  LoggerDereferenceState (state);
}

NTSTATUS
LoggerValidateLoadedModule (_In_ PEPROCESS Process, _In_ ULONG ModuleId,
                            _In_ PVOID ImageBase)
{
  KAPC_STATE apc_state;
  NTSTATUS status = STATUS_SUCCESS;
  PIMAGE_DOS_HEADER dos_header;
  PIMAGE_NT_HEADERS64 nt_headers;

  if (ImageBase == NULL || (ULONG_PTR)ImageBase < 0x10000)
    return STATUS_INVALID_IMAGE_FORMAT;

  KeStackAttachProcess (Process, &apc_state);
  __try
    {
      dos_header = (PIMAGE_DOS_HEADER)ImageBase;
      ProbeForRead (dos_header, sizeof (*dos_header), sizeof (ULONG));
      if (dos_header->e_magic != IMAGE_DOS_SIGNATURE
          || dos_header->e_lfanew <= 0 || dos_header->e_lfanew > 0x100000)
        status = STATUS_INVALID_IMAGE_FORMAT;
      else
        {
          nt_headers = (PIMAGE_NT_HEADERS64)((PUCHAR)ImageBase
                                             + dos_header->e_lfanew);
          ProbeForRead (nt_headers, sizeof (*nt_headers), sizeof (ULONG));
          if (nt_headers->Signature != IMAGE_NT_SIGNATURE
              || nt_headers->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64
              || nt_headers->OptionalHeader.Magic
                     != IMAGE_NT_OPTIONAL_HDR64_MAGIC
              || nt_headers->FileHeader.TimeDateStamp
                     != g_static_modules[ModuleId].timestamp
              || nt_headers->OptionalHeader.SizeOfImage
                     != g_static_modules[ModuleId].size_of_image)
            status = STATUS_INVALID_IMAGE_HASH;
        }
    }
  __except (LOGGER_HANDLE_MEMORY_EXCEPTION (GetExceptionCode ()))
    {
      status = GetExceptionCode ();
    }
  KeUnstackDetachProcess (&apc_state);
  return status;
}
