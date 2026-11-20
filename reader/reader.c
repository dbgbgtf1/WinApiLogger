#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include <windows.h>

#include "../common/protocol.h"
#include "generated/generated_names.h"

#define READER_LIST_BUFFER_SIZE (256u * 1024u)
#define READER_READ_BUFFER_SIZE (256u * 1024u)
#define READER_PATH L"\\\\.\\WinApiLogger"

typedef struct _READER_OPTIONS
{
  ULONGLONG StreamId;
  BOOLEAN HasStream;
  BOOLEAN Follow;
  BOOLEAN HasPid;
  ULONG Pid;
  BOOLEAN HasModule;
  const WCHAR *Module;
  BOOLEAN HasApi;
  const WCHAR *Api;
  BOOLEAN HasRva;
  ULONG Rva;
} READER_OPTIONS;

static volatile LONG g_StopRequested;

static BOOL WINAPI
ReaderConsoleControl (DWORD ControlType)
{
  UNREFERENCED_PARAMETER (ControlType);
  InterlockedExchange (&g_StopRequested, 1);
  return TRUE;
}

static void
ReaderPrintLastError (const WCHAR *Operation)
{
  DWORD error = GetLastError ();
  fwprintf (stderr, L"%ls: %lu\n", Operation, error);
}

static HANDLE
ReaderOpenDevice (void)
{
  HANDLE device = CreateFileW (READER_PATH, GENERIC_READ | GENERIC_WRITE,
                               FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (device == INVALID_HANDLE_VALUE)
    {
      ReaderPrintLastError (L"open WinApiLogger");
    }
  return device;
}

static BOOL
ReaderDeviceIoControl (HANDLE Device, DWORD Code, const void *Input,
                       DWORD InputLength, void *Output, DWORD OutputLength,
                       DWORD *Returned)
{
  DWORD returned = 0;
  if (!DeviceIoControl (Device, Code, (PVOID)Input, InputLength, Output,
                        OutputLength, &returned, NULL))
    {
      ReaderPrintLastError (L"DeviceIoControl");
      return FALSE;
    }
  if (Returned != NULL)
    {
      *Returned = returned;
    }
  return TRUE;
}

static BOOL
ReaderAddFilter (HANDLE Device, const WCHAR *ImageName)
{
  LOGGER_ADD_FILTER_REQUEST request;
  size_t length = wcslen (ImageName);
  if (length == 0 || length >= WIN_API_LOGGER_MAX_IMAGE_CHARS
      || wcschr (ImageName, L'\\') != NULL || wcschr (ImageName, L'/') != NULL)
    {
      fwprintf (stderr, L"invalid image basename\n");
      return FALSE;
    }
  ZeroMemory (&request, sizeof (request));
  request.Version = WIN_API_LOGGER_CLIENT_VERSION;
  request.ImageNameChars = (ULONG)(length + 1);
  memcpy (request.ImageName, ImageName, (length + 1) * sizeof (WCHAR));
  return ReaderDeviceIoControl (Device, WIN_API_LOGGER_IOCTL_ADD_FILTER,
                                &request, sizeof (request), NULL, 0, NULL);
}

static BOOL
ReaderResetFilter (HANDLE Device)
{
  return ReaderDeviceIoControl (Device, WIN_API_LOGGER_IOCTL_RESET_FILTER,
                                NULL, 0, NULL, 0, NULL);
}

static const CHAR *
ReaderStateText (ULONG State)
{
  switch (State)
    {
    case LoggerStreamInstalling:
      return "installing";
    case LoggerStreamActive:
      return "active";
    case LoggerStreamFailed:
      return "failed";
    case LoggerStreamExited:
      return "exited";
    default:
      return "unknown";
    }
}

static const CHAR *
ReaderFailureText (ULONG Reason)
{
  switch (Reason)
    {
    case LoggerFailureNone:
      return "none";
    case LoggerFailureProtectedProcess:
      return "protected process";
    case LoggerFailureCriticalProcess:
      return "critical process";
    case LoggerFailureWow64Process:
      return "WOW64 process";
    case LoggerFailureOutOfMemory:
      return "out of memory";
    case LoggerFailureMappingFailed:
      return "user mapping failed";
    case LoggerFailureCodeProtectionFailed:
      return "code protection failed";
    case LoggerFailureModuleMismatch:
      return "module identity mismatch";
    case LoggerFailureTargetProtectionFailed:
      return "target page protection failed";
    case LoggerFailurePatchMismatch:
      return "original bytes changed";
    case LoggerFailurePatchFailed:
      return "entry patch failed";
    case LoggerFailureRollbackFailed:
      return "patch rollback failed";
    case LoggerFailureStubAllocationFailed:
      return "near stub allocation failed";
    case LoggerFailureStubProtectionFailed:
      return "stub protection failed";
    case LoggerFailureInvalidModuleIdRva:
      return "invalid module id/rva";
    case LoggerFailurePrivateMappingFailed:
      return "private data mapping failed";
    case LoggerFailureLoggerMappingFailed:
      return "logger image mapping failed";
    case LoggerFailureQueueInitializationFailed:
      return "queue initialization failed";
    default:
      return "invalid state";
    }
}

static const char *
ReaderModuleName (ULONG ModuleId)
{
  ULONG low = 0;
  ULONG high = LOGGER_MODULE_NAME_ENTRY_COUNT;
  while (low < high)
    {
      ULONG middle = low + (high - low) / 2;
      if (g_module_name_entries[middle].module_id < ModuleId)
        low = middle + 1;
      else
        high = middle;
    }
  if (low < LOGGER_MODULE_NAME_ENTRY_COUNT
      && g_module_name_entries[low].module_id == ModuleId)
    return g_module_name_entries[low].base_name;
  return "unknown.dll";
}

static BOOL
ReaderListStreams (HANDLE Device, ULONGLONG AfterStreamId,
                   PLOGGER_STREAM_INFO *Streams, PULONG StreamCount)
{
  ULONG maximum_total = READER_LIST_BUFFER_SIZE / sizeof (LOGGER_STREAM_INFO);
  BYTE *buffer = (BYTE *)HeapAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY,
                                    READER_LIST_BUFFER_SIZE);
  PLOGGER_LIST_STREAMS_RESPONSE response;
  PLOGGER_LIST_STREAMS_REQUEST request;
  LOGGER_STREAM_INFO *streams;
  ULONG total = 0;
  ULONGLONG cursor = AfterStreamId;

  if (buffer == NULL)
    {
      SetLastError (ERROR_NOT_ENOUGH_MEMORY);
      ReaderPrintLastError (L"HeapAlloc list buffer");
      return FALSE;
    }
  streams = (PLOGGER_STREAM_INFO)HeapAlloc (
      GetProcessHeap (), HEAP_ZERO_MEMORY, READER_LIST_BUFFER_SIZE);
  if (streams == NULL)
    {
      HeapFree (GetProcessHeap (), 0, buffer);
      SetLastError (ERROR_NOT_ENOUGH_MEMORY);
      ReaderPrintLastError (L"HeapAlloc stream array");
      return FALSE;
    }

  response = (PLOGGER_LIST_STREAMS_RESPONSE)buffer;
  request = (PLOGGER_LIST_STREAMS_REQUEST)buffer;
  for (;;)
    {
      DWORD returned = 0;
      ULONG index;
      ZeroMemory (buffer, READER_LIST_BUFFER_SIZE);
      request->Version = WIN_API_LOGGER_CLIENT_VERSION;
      request->AfterStreamId = cursor;
      {
        ULONG fit
            = (READER_LIST_BUFFER_SIZE
               - (ULONG)FIELD_OFFSET (LOGGER_LIST_STREAMS_RESPONSE, Streams))
              / sizeof (LOGGER_STREAM_INFO);
        ULONG remaining = maximum_total - total;
        request->MaximumCount = fit < remaining ? fit : remaining;
      }
      if (!ReaderDeviceIoControl (Device, WIN_API_LOGGER_IOCTL_LIST_STREAMS,
                                  request, sizeof (*request), buffer,
                                  READER_LIST_BUFFER_SIZE, &returned))
        {
          HeapFree (GetProcessHeap (), 0, streams);
          HeapFree (GetProcessHeap (), 0, buffer);
          return FALSE;
        }
      if (returned
          < (DWORD)FIELD_OFFSET (LOGGER_LIST_STREAMS_RESPONSE, Streams))
        {
          break;
        }
      for (index = 0; index < response->Count && total < maximum_total;
           ++index)
        {
          streams[total++] = response->Streams[index];
          cursor = response->Streams[index].StreamId;
        }
      if (!response->More || response->Count == 0 || total >= maximum_total)
        {
          break;
        }
    }
  *Streams = streams;
  *StreamCount = total;
  HeapFree (GetProcessHeap (), 0, buffer);
  return TRUE;
}

static BOOL
ReaderModuleMatches (const WCHAR *Expected, const char *Actual)
{
  WCHAR widened[WIN_API_LOGGER_MAX_IMAGE_CHARS];
  size_t width;

  if (MultiByteToWideChar (CP_ACP, 0, Actual, -1, widened,
                           _countof (widened))
      == 0)
    return FALSE;
  if (_wcsicmp (Expected, widened) == 0)
    return TRUE;

  width = wcslen (widened);
  if (width >= 4 && _wcsicmp (widened + width - 4, L".dll") == 0)
    return FALSE;
  if (width + 4 >= _countof (widened))
    return FALSE;
  if (wcscat_s (widened, _countof (widened), L".dll") != 0)
    return FALSE;
  return _wcsicmp (Expected, widened) == 0;
}

static BOOL
ReaderMatchesFilters (const READER_OPTIONS *Options,
                      const LOGGER_DRIVER_RECORD *Record,
                      const LOGGER_NAME_ENTRY *Name)
{
  if (Options->HasPid && Options->Pid != Record->ProcessId)
    {
      return FALSE;
    }
  if (Options->HasRva && Options->Rva != Record->HookRva)
    {
      return FALSE;
    }
  if (Options->HasModule)
    {
      const char *module_name = ReaderModuleName (Record->ModuleId);
      if (!ReaderModuleMatches (Options->Module, module_name))
        return FALSE;
    }
  if (Options->HasApi)
    {
      CHAR utf8_or_ansi[512];
      WCHAR widened[512];
      size_t length;
      const char *candidate;
      if (Name == NULL)
        {
          return FALSE;
        }
      candidate = Name->canonical_name;
      length = strlen (candidate);
      if (length >= _countof (utf8_or_ansi))
        {
          return FALSE;
        }
      memcpy (utf8_or_ansi, candidate, length + 1);
      if (MultiByteToWideChar (CP_ACP, 0, utf8_or_ansi, -1, widened,
                               _countof (widened))
          == 0)
        {
          return FALSE;
        }
      if (_wcsicmp (Options->Api, widened) == 0)
        {
          return TRUE;
        }
      if (Name->aliases != NULL && *Name->aliases != '\0')
        {
          char aliases[2048];
          char *context = NULL;
          char *token;
          length = strlen (Name->aliases);
          if (length >= sizeof (aliases))
            {
              return FALSE;
            }
          memcpy (aliases, Name->aliases, length + 1);
          token = strtok_s (aliases, ";", &context);
          while (token != NULL)
            {
              if (MultiByteToWideChar (CP_ACP, 0, token, -1, widened,
                                       _countof (widened))
                      != 0
                  && _wcsicmp (Options->Api, widened) == 0)
                {
                  return TRUE;
                }
              token = strtok_s (NULL, ";", &context);
            }
        }
      return FALSE;
    }
  return TRUE;
}

static const LOGGER_NAME_ENTRY *
ReaderFindName (const LOGGER_DRIVER_RECORD *Record)
{
  ULONG low = 0;
  ULONG high = LOGGER_NAME_ENTRY_COUNT;
  while (low < high)
    {
      ULONG middle = low + (high - low) / 2;
      if (g_name_entries[middle].module_id < Record->ModuleId
          || (g_name_entries[middle].module_id == Record->ModuleId
              && g_name_entries[middle].hook_rva < Record->HookRva))
        {
          low = middle + 1;
        }
      else
        {
          high = middle;
        }
    }
  if (low < LOGGER_NAME_ENTRY_COUNT
      && g_name_entries[low].module_id == Record->ModuleId
      && g_name_entries[low].hook_rva == Record->HookRva)
    {
      return &g_name_entries[low];
    }
  return NULL;
}

static BOOL
ReaderFormatRecord (const READER_OPTIONS *Options,
                    const LOGGER_DRIVER_RECORD *Record,
                    _Out_writes_ (Chars) WCHAR *Destination,
                    _In_ size_t Chars)
{
  const LOGGER_NAME_ENTRY *name = ReaderFindName (Record);
  const char *module_name = ReaderModuleName (Record->ModuleId);
  const char *api_name = name != NULL ? name->canonical_name : "<unknown>";
  WCHAR caller_module[WIN_API_LOGGER_MODULE_NAME_CHARS];
  size_t caller_chars;

  if (!ReaderMatchesFilters (Options, Record, name))
    return FALSE;
  if (Record->CallerModuleChars == 0)
    return swprintf_s (Destination, Chars,
                       L"%lu.%lu unknown-0x%llX called %hs!%hs",
                       Record->ProcessId, Record->ThreadId,
                       (unsigned long long)Record->CallerAddress, module_name,
                       api_name) >= 0;

  caller_chars = Record->CallerModuleChars;
  if (caller_chars >= WIN_API_LOGGER_MODULE_NAME_CHARS)
    caller_chars = WIN_API_LOGGER_MODULE_NAME_CHARS - 1;
  memcpy (caller_module, Record->CallerModule,
          caller_chars * sizeof (WCHAR));
  caller_module[caller_chars] = L'\0';
  return swprintf_s (Destination, Chars,
                     L"%lu.%lu %ls:0x%X called %hs!%hs", Record->ProcessId,
                     Record->ThreadId, caller_module, Record->CallerRva,
                     module_name, api_name) >= 0;
}

static void
ReaderPrintRecord (const READER_OPTIONS *Options,
                   const LOGGER_DRIVER_RECORD *Record)
{
  WCHAR line[512];

  if (!ReaderFormatRecord (Options, Record, line, _countof (line)))
    return;
  wprintf (L"%ls\n", line);
  fflush (stdout);
}

static BOOL
ReaderReadStreamOnce (HANDLE Device, ULONGLONG StreamId,
                      const READER_OPTIONS *Options, PULONG RecordCount,
                      PULONG StreamState, PULONG FailureReason)
{
  BYTE *buffer = (BYTE *)HeapAlloc (GetProcessHeap (), HEAP_ZERO_MEMORY,
                                    READER_READ_BUFFER_SIZE);
  PLOGGER_READ_STREAM_REQUEST request;
  PLOGGER_READ_STREAM_RESPONSE response;
  DWORD returned = 0;
  ULONG index;

  if (buffer == NULL)
    {
      SetLastError (ERROR_NOT_ENOUGH_MEMORY);
      ReaderPrintLastError (L"HeapAlloc read buffer");
      return FALSE;
    }
  request = (PLOGGER_READ_STREAM_REQUEST)buffer;
  request->Version = WIN_API_LOGGER_CLIENT_VERSION;
  request->StreamId = StreamId;
  request->MaximumBytes
      = READER_READ_BUFFER_SIZE
        - FIELD_OFFSET (LOGGER_READ_STREAM_RESPONSE, Records);
  if (!ReaderDeviceIoControl (Device, WIN_API_LOGGER_IOCTL_READ_STREAM,
                              request, sizeof (*request), buffer,
                              READER_READ_BUFFER_SIZE, &returned))
    {
      HeapFree (GetProcessHeap (), 0, buffer);
      return FALSE;
    }
  response = (PLOGGER_READ_STREAM_RESPONSE)buffer;
  if (returned < (DWORD)FIELD_OFFSET (LOGGER_READ_STREAM_RESPONSE, Records))
    {
      HeapFree (GetProcessHeap (), 0, buffer);
      SetLastError (ERROR_BAD_LENGTH);
      ReaderPrintLastError (L"READ_STREAM response");
      return FALSE;
    }
  for (index = 0; index < response->RecordCount; ++index)
    {
      ReaderPrintRecord (Options, &response->Records[index]);
    }
  *RecordCount = response->RecordCount;
  *StreamState = response->State;
  *FailureReason = response->FailureReason;
  HeapFree (GetProcessHeap (), 0, buffer);
  return TRUE;
}

static BOOL
ReaderReadStream (HANDLE Device, ULONGLONG StreamId,
                  const READER_OPTIONS *Options)
{
  for (;;)
    {
      ULONG records = 0;
      ULONG state = LoggerStreamInstalling;
      ULONG failure = LoggerFailureNone;
      if (!ReaderReadStreamOnce (Device, StreamId, Options, &records, &state,
                                 &failure))
        {
          return FALSE;
        }
      if (!Options->Follow)
        {
          return TRUE;
        }
      if (state == LoggerStreamExited && records == 0)
        {
          return TRUE;
        }
      if (state == LoggerStreamFailed)
        {
          fwprintf (stderr, L"stream %llu failed: %hs\n", StreamId,
                    ReaderFailureText (failure));
          return TRUE;
        }
      if (g_StopRequested)
        {
          return TRUE;
        }
      Sleep (100);
    }
}

static int
ReaderCommandList (HANDLE Device)
{
  PLOGGER_STREAM_INFO streams = NULL;
  ULONG count = 0;
  ULONG index;
  if (!ReaderListStreams (Device, 0, &streams, &count))
    {
      return 1;
    }
  for (index = 0; index < count; ++index)
    {
      WCHAR failure[96];
      if (streams[index].FailureStatus == 0)
        {
          swprintf_s (failure, _countof (failure), L"%hs",
                      ReaderFailureText (streams[index].FailureReason));
        }
      else
        {
          swprintf_s (failure, _countof (failure), L"%hs (0x%08X)",
                      ReaderFailureText (streams[index].FailureReason),
                      streams[index].FailureStatus);
        }
      wprintf (L"%llu\t%lu\t%hs\t%ls\t%ls\tloaded=0x%X\tinstalled=0x%X\tfailure-source=0x%llX\tfailure-destination=0x%llX\n",
               streams[index].StreamId,
               streams[index].ProcessId,
               ReaderStateText (streams[index].State), failure,
               streams[index].ImageName, streams[index].LoadedModuleMask,
               streams[index].InstalledModuleMask,
               streams[index].FailureSource,
               streams[index].FailureDestination);
    }
  HeapFree (GetProcessHeap (), 0, streams);
  return 0;
}

static int
ReaderCommandWatch (HANDLE Device, const READER_OPTIONS *Options)
{
  do
    {
      PLOGGER_STREAM_INFO streams = NULL;
      ULONG count = 0;
      ULONG index;
      if (!ReaderListStreams (Device, 0, &streams, &count))
        {
          return 1;
        }
      for (index = 0; index < count; ++index)
        {
          ULONG records = 0;
          ULONG state = LoggerStreamInstalling;
          ULONG failure = LoggerFailureNone;
          do
            {
              if (!ReaderReadStreamOnce (Device, streams[index].StreamId,
                                         Options, &records, &state, &failure))
                {
                  HeapFree (GetProcessHeap (), 0, streams);
                  return 1;
                }
            }
          while (records != 0);
        }
      HeapFree (GetProcessHeap (), 0, streams);
      if (!Options->Follow || g_StopRequested)
        {
          break;
        }
      Sleep (200);
    }
  while (!g_StopRequested);
  return 0;
}

static void
ReaderUsage (const WCHAR *Program)
{
  wprintf (L"Usage:\n"
           L"  %ls filter add <image.exe>\n"
           L"  %ls filter reset\n"
           L"  %ls list\n"
           L"  %ls read --stream <id> [--follow] [filters]\n"
           L"  %ls watch [--follow] [filters]\n"
           L"\n"
           L"Filters: --pid <pid> --module <name> --api <name> --rva <hex>\n",
           Program, Program, Program, Program, Program);
}

static BOOL
ReaderParseUInt64 (const WCHAR *Text, ULONGLONG *Value)
{
  WCHAR *end = NULL;
  errno = 0;
  *Value = _wcstoui64 (Text, &end, 0);
  return errno == 0 && end != Text && *end == L'\0';
}

static BOOL
ReaderParseOptions (int ArgumentCount, WCHAR **Arguments, int Start,
                    READER_OPTIONS *Options)
{
  int index;
  ZeroMemory (Options, sizeof (*Options));
  for (index = Start; index < ArgumentCount; ++index)
    {
      const WCHAR *argument = Arguments[index];
      if (_wcsicmp (argument, L"--follow") == 0)
        {
          Options->Follow = TRUE;
        }
      else if (_wcsicmp (argument, L"--stream") == 0)
        {
          if (++index >= ArgumentCount
              || !ReaderParseUInt64 (Arguments[index], &Options->StreamId))
            {
              return FALSE;
            }
          Options->HasStream = TRUE;
        }
      else if (_wcsicmp (argument, L"--pid") == 0)
        {
          ULONGLONG value;
          if (++index >= ArgumentCount
              || !ReaderParseUInt64 (Arguments[index], &value)
              || value > MAXDWORD)
            {
              return FALSE;
            }
          Options->HasPid = TRUE;
          Options->Pid = (ULONG)value;
        }
      else if (_wcsicmp (argument, L"--module") == 0)
        {
          if (++index >= ArgumentCount)
            {
              return FALSE;
            }
          Options->HasModule = TRUE;
          Options->Module = Arguments[index];
        }
      else if (_wcsicmp (argument, L"--api") == 0)
        {
          if (++index >= ArgumentCount)
            {
              return FALSE;
            }
          Options->HasApi = TRUE;
          Options->Api = Arguments[index];
        }
      else if (_wcsicmp (argument, L"--rva") == 0)
        {
          ULONGLONG value;
          if (++index >= ArgumentCount
              || !ReaderParseUInt64 (Arguments[index], &value)
              || value > MAXDWORD)
            {
              return FALSE;
            }
          Options->HasRva = TRUE;
          Options->Rva = (ULONG)value;
        }
      else
        {
          return FALSE;
        }
    }
  return TRUE;
}

int
wmain (int argc, WCHAR **argv)
{
  HANDLE device;
  int result = 1;

  SetConsoleCtrlHandler (ReaderConsoleControl, TRUE);
  if (argc < 2)
    {
      ReaderUsage (argv[0]);
      return 1;
    }
  device = ReaderOpenDevice ();
  if (device == INVALID_HANDLE_VALUE)
    {
      return 1;
    }

  if (_wcsicmp (argv[1], L"filter") == 0)
    {
      if (argc == 3 && _wcsicmp (argv[2], L"reset") == 0)
        {
          result = ReaderResetFilter (device) ? 0 : 1;
        }
      else if (argc == 4 && _wcsicmp (argv[2], L"add") == 0)
        {
          result = ReaderAddFilter (device, argv[3]) ? 0 : 1;
        }
      else
        {
          ReaderUsage (argv[0]);
        }
    }
  else if (_wcsicmp (argv[1], L"list") == 0)
    {
      result = argc == 2 ? ReaderCommandList (device) : 1;
      if (argc != 2)
        {
          ReaderUsage (argv[0]);
        }
    }
  else if (_wcsicmp (argv[1], L"read") == 0)
    {
      READER_OPTIONS options;
      if (ReaderParseOptions (argc, argv, 2, &options) && options.HasStream)
        {
          result
              = ReaderReadStream (device, options.StreamId, &options) ? 0 : 1;
        }
      else
        {
          ReaderUsage (argv[0]);
        }
    }
  else if (_wcsicmp (argv[1], L"watch") == 0)
    {
      READER_OPTIONS options;
      if (ReaderParseOptions (argc, argv, 2, &options))
        {
          result = ReaderCommandWatch (device, &options);
        }
      else
        {
          ReaderUsage (argv[0]);
        }
    }
  else
    {
      ReaderUsage (argv[0]);
    }

  CloseHandle (device);
  return result;
}
