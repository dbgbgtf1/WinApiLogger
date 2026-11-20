#ifndef WIN_API_LOGGER_DRIVER_STATE_H
#define WIN_API_LOGGER_DRIVER_STATE_H

#include "logger_internal.h"

/*
 * Producers: LoadImage installer and rollback.  Consumers: state aggregation,
 * process cleanup, and unload safety checks.  Logger and reader never access
 * it.
 */
typedef struct _LOGGER_MODULE_STATE
{
  BOOLEAN Loaded;
  BOOLEAN StubProtected;
  UINT32 FailureReason;
  UINT64 ImageBase;
  UINT32 ImageSize;
  PVOID StubBase;
  SIZE_T StubSize;
  PUCHAR ExportInstalled;
} LOGGER_MODULE_STATE;

/*
 * Producer: create-process callback.  Consumers: image installer, queue/IOCTL
 * paths, exit cleanup, and unload safety checks.  A reader owns a reference
 * until its IOCTL completes; the final reference releases all mappings.
 */
struct _LOGGER_PROCESS_STATE
{
  LIST_ENTRY ListEntry;
  PEPROCESS Process;
  HANDLE ProcessId;
  ULONGLONG StreamId;
  WCHAR ImageName[LOGGER_IMAGE_NAME_CHARS];
  USHORT ImageNameChars;
  ULONG State;
  ULONG FailureReason;
  ULONG FailureStatus;
  UINT64 FailureSource;
  UINT64 FailureDestination;
  volatile LONG ReferenceCount;
  BOOLEAN DeletePending;
  BOOLEAN Exiting;
  BOOLEAN Initialized;

  LOGGER_USER_BUFFER Data;
  PVOID LoggerVa;
  LOGGER_CONTEXT *Context;
  LOGGER_QUEUE_HEADER *QueueHeader;
  LOGGER_MODULE_STATE Modules[WIN_API_LOGGER_MODULE_COUNT];

  ERESOURCE InstallResource;
  ERESOURCE QueueResource;
};

extern LIST_ENTRY g_ProcessStates;
extern KSPIN_LOCK g_ProcessStatesLock;

BOOLEAN LoggerGetImageBaseName (_In_ PCUNICODE_STRING FullName,
                                _Out_writes_ (LOGGER_IMAGE_NAME_CHARS)
                                    PWCHAR BaseName,
                                _Out_ PUSHORT BaseNameChars);
ULONG LoggerFindStaticModule (_In_ PCUNICODE_STRING BaseName);
NTSTATUS LoggerAddFilter (_In_ PCUNICODE_STRING BaseName);
NTSTATUS LoggerResetFilter (void);

LOGGER_PROCESS_STATE *LoggerFindStateByProcess (_In_ PEPROCESS Process);
LOGGER_PROCESS_STATE *LoggerFindStateByStreamId (_In_ ULONGLONG StreamId);
VOID LoggerDereferenceState (_In_ LOGGER_PROCESS_STATE *State);
VOID LoggerRecordFailure (_Inout_ LOGGER_PROCESS_STATE *State,
                          _In_ ULONG Reason);
VOID LoggerRecordModuleFailure (_Inout_ LOGGER_PROCESS_STATE *State,
                                _In_ ULONG ModuleId, _In_ ULONG Reason);

#endif
