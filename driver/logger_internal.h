#ifndef WIN_API_LOGGER_DRIVER_LOGGER_INTERNAL_H
#define WIN_API_LOGGER_DRIVER_LOGGER_INTERNAL_H

#include <ntifs.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <stdint.h>

#include "../common/protocol.h"
#include "generated/generated_metadata.h"
#include "generated/generated_payload.h"

#define LOGGER_DRIVER_TAG 'gLoW'
#define LOGGER_DEVICE_TAG 'dLoW'
#define LOGGER_MAPPING_TAG 'mLoW'
#define LOGGER_STATE_TAG 'sLoW'

#define LOGGER_IMAGE_NAME_CHARS WIN_API_LOGGER_MAX_IMAGE_CHARS
#define LOGGER_ENTRY_PATCH_BYTES 5u
#define LOGGER_CONTEXT_OFFSET 0u
#define LOGGER_QUEUE_HEADER_OFFSET WIN_API_LOGGER_CONTEXT_SIZE
#define LOGGER_QUEUE_RECORDS_OFFSET                                           \
  (WIN_API_LOGGER_CONTEXT_SIZE + WIN_API_LOGGER_QUEUE_HEADER_SIZE)
#define LOGGER_PRIVATE_DATA_SIZE WIN_API_LOGGER_PRIVATE_DATA_SIZE
#define LOGGER_LOADED_MODULE_INITIAL_CAPACITY 256u
#define LOGGER_LOADED_MODULE_LIMIT 4096u

#define LOGGER_PROCESS_QUERY_LIMITED_INFORMATION 0x1000u
#define LOGGER_HANDLE_MEMORY_EXCEPTION(Code)                                  \
  (((Code) == STATUS_ACCESS_VIOLATION                                         \
    || (Code) == STATUS_GUARD_PAGE_VIOLATION                                  \
    || (Code) == STATUS_IN_PAGE_ERROR)                                        \
       ? EXCEPTION_EXECUTE_HANDLER                                            \
       : EXCEPTION_CONTINUE_SEARCH)

typedef struct _LOGGER_USER_BUFFER
{
  PMDL Mdl;
  PVOID KernelVa;
  PVOID UserVa;
  SIZE_T Size;
  BOOLEAN Mapped;
} LOGGER_USER_BUFFER;

/*
 * One page-rounded non-paged backing allocation is shared by all processes.
 * Producer: DriverEntry through LoggerMemoryInitialize.  Consumers:
 * per-process LoggerVa.  Destruction: DriverUnload after the last target
 * stream exits.
 */
typedef struct _LOGGER_SHARED_IMAGE
{
  HANDLE Section;
  SIZE_T Size;
  volatile LONG MappingCount;
  BOOLEAN Initialized;
  KMUTEX InitializationMutex;
} LOGGER_SHARED_IMAGE;

typedef struct _LOGGER_PROCESS_STATE LOGGER_PROCESS_STATE;
typedef struct _LOGGER_LOADED_MODULE
{
  ULONG_PTR ImageBase;
  ULONG SizeOfImage;
  WCHAR BaseName[WIN_API_LOGGER_MODULE_NAME_CHARS];
} LOGGER_LOADED_MODULE;

typedef struct _LOGGER_MODULE_SNAPSHOT
{
  LOGGER_LOADED_MODULE *Entries;
  ULONG Count;
  ULONG Capacity;
} LOGGER_MODULE_SNAPSHOT;

typedef BOOLEAN (*LOGGER_NEAR_STUB_VALIDATOR) (_In_ PVOID Candidate,
                                              _In_opt_ PVOID Context);

extern LOGGER_SHARED_IMAGE g_LoggerImage;

extern NTSTATUS ZwProtectVirtualMemory (_In_ HANDLE ProcessHandle,
                                        _Inout_ PVOID *BaseAddress,
                                        _Inout_ PSIZE_T RegionSize,
                                        _In_ ULONG NewProtect,
                                        _Out_ PULONG OldProtect);

extern NTSTATUS ZwQueryInformationProcess (
    _In_ HANDLE ProcessHandle, _In_ ULONG ProcessInformationClass,
    _Out_writes_bytes_ (ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength, _Out_opt_ PULONG ReturnLength);

extern NTSYSAPI PVOID NTAPI PsGetProcessWow64Process (_In_ PEPROCESS Process);
extern NTSYSAPI PPEB NTAPI PsGetProcessPeb (_In_ PEPROCESS Process);

NTSTATUS LoggerMemoryInitialize (void);
VOID LoggerMemoryShutdown (void);
NTSTATUS LoggerInitializePrivateData (_Inout_ LOGGER_PROCESS_STATE *State);
VOID LoggerFreePrivateData (_Inout_ LOGGER_PROCESS_STATE *State);
NTSTATUS LoggerInitializeLoggerView (_Inout_ LOGGER_PROCESS_STATE *State);
VOID LoggerFreeLoggerView (_Inout_ LOGGER_PROCESS_STATE *State);
NTSTATUS LoggerAllocateNearStub (_In_ PEPROCESS Process, _In_ PVOID ImageBase,
                                 _In_ SIZE_T Size,
                                 _In_opt_ LOGGER_NEAR_STUB_VALIDATOR Validator,
                                 _In_opt_ PVOID Context,
                                 _Out_ PVOID *StubBase);
VOID LoggerFreeNearStub (_In_ PEPROCESS Process, _In_ PVOID StubBase,
                         _In_ SIZE_T Size);
NTSTATUS LoggerProtectUserCode (_In_ PEPROCESS Process, _In_ PVOID Address,
                                _In_ SIZE_T Size);
NTSTATUS LoggerWriteUserRange (_In_ PEPROCESS Process, _In_ PVOID Address,
                               _In_reads_bytes_ (Size) const VOID *Source,
                               _In_ SIZE_T Size);
NTSTATUS LoggerValidateLoadedModule (_In_ PEPROCESS Process,
                                     _In_ ULONG ModuleId,
                                     _In_ PVOID ImageBase);
NTSTATUS LoggerInstallModule (_Inout_ LOGGER_PROCESS_STATE *State,
                              _In_ ULONG ModuleId, _In_ PVOID ImageBase,
                              _In_ SIZE_T ImageSize);
VOID LoggerInstallLoadedModules (_Inout_ LOGGER_PROCESS_STATE *State);
NTSTATUS LoggerBuildLoadedModuleSnapshot (
    _Inout_ LOGGER_PROCESS_STATE *State,
    _Inout_ LOGGER_MODULE_SNAPSHOT *Snapshot);
VOID LoggerFreeLoadedModuleSnapshot (
    _Inout_ LOGGER_MODULE_SNAPSHOT *Snapshot);
const LOGGER_LOADED_MODULE *LoggerFindLoadedModule (
    _In_ const LOGGER_MODULE_SNAPSHOT *Snapshot, _In_ ULONG_PTR Address);
NTSTATUS LoggerWriteTargetRange (_In_ PEPROCESS Process, _In_ PVOID Address,
                                 _In_reads_bytes_opt_ (Size)
                                     const VOID *ExpectedOriginal,
                                 _In_reads_bytes_ (Size)
                                     const VOID *Replacement,
                                 _In_ SIZE_T Size, _Out_opt_ PUCHAR Original,
                                 _Out_opt_ PBOOLEAN BytesChanged);

NTSTATUS LoggerInitializeStubLayout (void);
ULONG LoggerExportStubOffset (_In_ ULONG ExportIndex);
ULONG LoggerExportStubSize (_In_ ULONG ExportIndex);
ULONG LoggerModuleStubSize (_In_ ULONG ModuleId);

NTSTATUS LoggerInitializeQueue (_Inout_ LOGGER_PROCESS_STATE *State);
BOOLEAN LoggerQueueHasRecords (_Inout_ LOGGER_PROCESS_STATE *State,
                               _In_ ULONG MaximumBytes);
ULONG LoggerReadQueue (_Inout_ LOGGER_PROCESS_STATE *State,
                       _In_ const LOGGER_MODULE_SNAPSHOT *Snapshot,
                       _Out_writes_bytes_ (MaximumBytes) PUCHAR Destination,
                       _In_ ULONG MaximumBytes);

NTSTATUS LoggerProcessInitialize (void);
VOID LoggerProcessShutdown (void);
BOOLEAN LoggerProcessHasLiveStates (void);

_Function_class_ (DRIVER_DISPATCH)
NTSTATUS LoggerCreateClose (_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);
_Function_class_ (DRIVER_DISPATCH)
NTSTATUS LoggerDeviceControl (_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp);

VOID LoggerCreateProcessNotify (_Inout_ PEPROCESS Process,
                                _In_ HANDLE ProcessId,
                                _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo);
VOID LoggerRememberPendingImage (_In_ HANDLE ProcessId, _In_ ULONG ModuleId,
                                 _In_ PVOID ImageBase,
                                 _In_ SIZE_T ImageSize);
VOID LoggerLoadImageNotify (_In_opt_ PUNICODE_STRING FullImageName,
                            _In_ HANDLE ProcessId, _In_ PIMAGE_INFO ImageInfo);

#endif
