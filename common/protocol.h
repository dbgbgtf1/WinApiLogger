#ifndef WIN_API_LOGGER_PROTOCOL_H
#define WIN_API_LOGGER_PROTOCOL_H

#ifdef _KERNEL_MODE
#include <ntddk.h>
typedef PUCHAR LOGGER_USER_POINTER;
#elif defined(_LOGGER_FREESTANDING)
#include <stddef.h>
#include <stdint.h>
typedef uint8_t UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef uint16_t WCHAR;
typedef uint8_t *LOGGER_USER_POINTER;
#else
#include <windows.h>
typedef unsigned char *LOGGER_USER_POINTER;
#endif

#define WIN_API_LOGGER_DEVICE_NAME L"\\Device\\WinApiLogger"
#define WIN_API_LOGGER_SYMBOLIC_NAME L"\\DosDevices\\WinApiLogger"

#define WIN_API_LOGGER_CLIENT_VERSION 4u
#define WIN_API_LOGGER_MODULE_COUNT 3u
#define WIN_API_LOGGER_MAX_FILTERS 64u
#define WIN_API_LOGGER_MAX_IMAGE_CHARS 260u
#define WIN_API_LOGGER_MODULE_NAME_CHARS 16u
#define WIN_API_LOGGER_QUEUE_SIZE (256u * 1024u)
#define WIN_API_LOGGER_QUEUE_HEADER_SIZE 64u
#define WIN_API_LOGGER_QUEUE_DATA_SIZE                                        \
  (WIN_API_LOGGER_QUEUE_SIZE - WIN_API_LOGGER_QUEUE_HEADER_SIZE)
#define WIN_API_LOGGER_LOG_RECORD_SIZE 32u
#define WIN_API_LOGGER_DRIVER_RECORD_SIZE 72u
#define WIN_API_LOGGER_QUEUE_CAPACITY                                         \
  (WIN_API_LOGGER_QUEUE_DATA_SIZE / WIN_API_LOGGER_LOG_RECORD_SIZE)
#define WIN_API_LOGGER_CONTEXT_SIZE 64u
#define WIN_API_LOGGER_PRIVATE_DATA_SIZE                                      \
  (WIN_API_LOGGER_CONTEXT_SIZE + WIN_API_LOGGER_QUEUE_SIZE)

#define WIN_API_LOGGER_CONTEXT_MAGIC 0x314C52444E574157ULL
#define WIN_API_LOGGER_QUEUE_MAGIC 0x315145554E574157ULL

#define WIN_API_LOGGER_CTL_TYPE 0x8000u
#define WIN_API_LOGGER_IOCTL_ADD_FILTER                                       \
  CTL_CODE (WIN_API_LOGGER_CTL_TYPE, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define WIN_API_LOGGER_IOCTL_RESET_FILTER                                     \
  CTL_CODE (WIN_API_LOGGER_CTL_TYPE, 0x802, METHOD_BUFFERED, FILE_WRITE_DATA)
#define WIN_API_LOGGER_IOCTL_LIST_STREAMS                                     \
  CTL_CODE (WIN_API_LOGGER_CTL_TYPE, 0x803, METHOD_BUFFERED, FILE_READ_DATA)
#define WIN_API_LOGGER_IOCTL_READ_STREAM                                      \
  CTL_CODE (WIN_API_LOGGER_CTL_TYPE, 0x804, METHOD_BUFFERED, FILE_READ_DATA)

#pragma pack(push, 1)

typedef struct _LOGGER_LOG_RECORD
{
  UINT8 Length;
  UINT8 Version;
  UINT16 Reserved;
  UINT32 ProcessId;
  UINT32 ThreadId;
  UINT32 ModuleId;
  UINT32 HookRva;
  UINT32 Reserved2;
  UINT64 CallerAddress;
} LOGGER_LOG_RECORD;

typedef struct _LOGGER_DRIVER_RECORD
{
  UINT8 Length;
  UINT8 Version;
  UINT16 Reserved;
  UINT32 ProcessId;
  UINT32 ThreadId;
  UINT32 ModuleId;
  UINT32 HookRva;
  UINT32 CallerRva;
  UINT32 CallerModuleChars;
  UINT32 Reserved2;
  UINT64 CallerAddress;
  WCHAR CallerModule[WIN_API_LOGGER_MODULE_NAME_CHARS];
} LOGGER_DRIVER_RECORD;

#pragma pack(pop)
#pragma pack(push, 8)

/*
 * Mapped RW into each target process.  Producer: process callback.  Consumers:
 * shared logger and READ_STREAM.  Lifetime: process stream lifetime.
 */
typedef struct _LOGGER_CONTEXT
{
  UINT64 Magic;
  UINT32 Version;
  UINT32 ProcessId;
  UINT64 QueueVa;
  UINT32 QueueSize;
  UINT32 QueueCapacity;
  UINT8 Reserved[32];
} LOGGER_CONTEXT;

typedef struct _LOGGER_QUEUE_HEADER
{
  volatile UINT64 Head;
  volatile UINT64 Tail;
  volatile UINT64 Dropped;
  UINT64 Magic;
  UINT32 Capacity;
  UINT32 RecordStride;
  UINT8 Reserved[24];
} LOGGER_QUEUE_HEADER;

#pragma pack(pop)
#pragma pack(push, 1)

typedef struct _LOGGER_ADD_FILTER_REQUEST
{
  UINT32 Version;
  UINT32 ImageNameChars;
  WCHAR ImageName[WIN_API_LOGGER_MAX_IMAGE_CHARS];
} LOGGER_ADD_FILTER_REQUEST;

typedef enum _LOGGER_STREAM_STATE
{
  LoggerStreamInstalling = 0,
  LoggerStreamActive = 1,
  LoggerStreamFailed = 2,
  LoggerStreamExited = 3
} LOGGER_STREAM_STATE;

typedef enum _LOGGER_FAILURE_REASON
{
  LoggerFailureNone = 0,
  LoggerFailureProtectedProcess = 1,
  LoggerFailureCriticalProcess = 2,
  LoggerFailureWow64Process = 3,
  LoggerFailureOutOfMemory = 4,
  LoggerFailureMappingFailed = 5,
  LoggerFailureCodeProtectionFailed = 6,
  LoggerFailureModuleMismatch = 7,
  LoggerFailureTargetProtectionFailed = 8,
  LoggerFailurePatchMismatch = 9,
  LoggerFailurePatchFailed = 10,
  LoggerFailureRollbackFailed = 11,
  LoggerFailureInvalidState = 12,
  LoggerFailureStubAllocationFailed = 13,
  LoggerFailureStubProtectionFailed = 14,
  LoggerFailureInvalidModuleIdRva = 15,
  LoggerFailurePrivateMappingFailed = 16,
  LoggerFailureLoggerMappingFailed = 17,
  LoggerFailureQueueInitializationFailed = 18,
  LoggerFailureRipRelocationFailed = 19
} LOGGER_FAILURE_REASON;

typedef struct _LOGGER_STREAM_INFO
{
  UINT64 StreamId;
  UINT32 ProcessId;
  UINT32 State;
  UINT32 FailureReason;
  UINT32 FailureStatus;
  UINT32 LoadedModuleMask;
  UINT32 InstalledModuleMask;
  UINT64 FailureSource;
  UINT64 FailureDestination;
  UINT32 ImageNameChars;
  WCHAR ImageName[WIN_API_LOGGER_MAX_IMAGE_CHARS];
} LOGGER_STREAM_INFO;

typedef struct _LOGGER_LIST_STREAMS_REQUEST
{
  UINT32 Version;
  UINT32 Offset;
  UINT32 MaximumCount;
  UINT32 Reserved;
  UINT64 AfterStreamId;
} LOGGER_LIST_STREAMS_REQUEST;

typedef struct _LOGGER_LIST_STREAMS_RESPONSE
{
  UINT32 Version;
  UINT32 Count;
  UINT32 More;
  UINT32 Reserved;
  LOGGER_STREAM_INFO Streams[1];
} LOGGER_LIST_STREAMS_RESPONSE;

typedef struct _LOGGER_READ_STREAM_REQUEST
{
  UINT32 Version;
  UINT32 MaximumBytes;
  UINT64 StreamId;
} LOGGER_READ_STREAM_REQUEST;

typedef struct _LOGGER_READ_STREAM_RESPONSE
{
  UINT32 Version;
  UINT32 RecordCount;
  UINT32 BytesReturned;
  UINT32 State;
  UINT32 FailureReason;
  UINT32 FailureStatus;
  LOGGER_DRIVER_RECORD Records[1];
} LOGGER_READ_STREAM_RESPONSE;

typedef LOGGER_ADD_FILTER_REQUEST *PLOGGER_ADD_FILTER_REQUEST;
typedef LOGGER_STREAM_INFO *PLOGGER_STREAM_INFO;
typedef LOGGER_LIST_STREAMS_REQUEST *PLOGGER_LIST_STREAMS_REQUEST;
typedef LOGGER_LIST_STREAMS_RESPONSE *PLOGGER_LIST_STREAMS_RESPONSE;
typedef LOGGER_READ_STREAM_REQUEST *PLOGGER_READ_STREAM_REQUEST;
typedef LOGGER_READ_STREAM_RESPONSE *PLOGGER_READ_STREAM_RESPONSE;

#pragma pack(pop)

#endif
