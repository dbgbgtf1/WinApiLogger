#include <ntifs.h>

#include "state.h"

static NTSTATUS
LoggerHandleAddFilter (_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
  PLOGGER_ADD_FILTER_REQUEST request;
  UNICODE_STRING base_name;
  ULONG index;
  USHORT chars;

  if (Stack->Parameters.DeviceIoControl.InputBufferLength
      < sizeof (LOGGER_ADD_FILTER_REQUEST))
    return STATUS_BUFFER_TOO_SMALL;
  request = (PLOGGER_ADD_FILTER_REQUEST)Irp->AssociatedIrp.SystemBuffer;
  if (request->Version != WIN_API_LOGGER_CLIENT_VERSION
      || request->ImageNameChars <= 1
      || request->ImageNameChars >= WIN_API_LOGGER_MAX_IMAGE_CHARS)
    return STATUS_INVALID_PARAMETER;

  chars = (USHORT)request->ImageNameChars;
  if (request->ImageName[chars - 1] != UNICODE_NULL)
    return STATUS_INVALID_PARAMETER;
  for (index = 0; index < chars; ++index)
    {
      if (request->ImageName[index] == L'\\'
          || request->ImageName[index] == L'/')
        return STATUS_INVALID_PARAMETER;
    }

  base_name.Buffer = request->ImageName;
  base_name.Length = (chars - 1u) * sizeof (WCHAR);
  base_name.MaximumLength = chars * sizeof (WCHAR);
  return LoggerAddFilter (&base_name);
}

static VOID
LoggerFillStreamInfo (_Out_ PLOGGER_STREAM_INFO Destination,
                      _In_ const LOGGER_PROCESS_STATE *State)
{
  ULONG index;

  RtlZeroMemory (Destination, sizeof (*Destination));
  Destination->StreamId = State->StreamId;
  Destination->ProcessId = (UINT32)(ULONG_PTR)State->ProcessId;
  Destination->State = State->State;
  Destination->FailureReason = State->FailureReason;
  Destination->FailureStatus = State->FailureStatus;
  Destination->FailureSource = State->FailureSource;
  Destination->FailureDestination = State->FailureDestination;
  for (index = 0; index < WIN_API_LOGGER_MODULE_COUNT; ++index)
    {
      if (State->Modules[index].Loaded)
        Destination->LoadedModuleMask |= 1u << index;
      if (State->Modules[index].StubProtected)
        Destination->InstalledModuleMask |= 1u << index;
    }
  Destination->ImageNameChars = State->ImageNameChars + 1u;
  RtlCopyMemory (Destination->ImageName, State->ImageName,
                 Destination->ImageNameChars * sizeof (WCHAR));
}

static NTSTATUS
LoggerHandleListStreams (_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
  PLOGGER_LIST_STREAMS_REQUEST request = NULL;
  PLOGGER_LIST_STREAMS_RESPONSE response;
  ULONG output_length = Stack->Parameters.DeviceIoControl.OutputBufferLength;
  ULONG maximum_count;
  ULONG count = 0;
  ULONG64 after = 0;
  BOOLEAN more = FALSE;
  KIRQL old_irql;
  PLIST_ENTRY entry;

  if (output_length
      < sizeof (LOGGER_LIST_STREAMS_RESPONSE) - sizeof (LOGGER_STREAM_INFO))
    return STATUS_BUFFER_TOO_SMALL;
  maximum_count
      = (output_length - FIELD_OFFSET (LOGGER_LIST_STREAMS_RESPONSE, Streams))
        / sizeof (LOGGER_STREAM_INFO);
  if (Stack->Parameters.DeviceIoControl.InputBufferLength
      >= sizeof (LOGGER_LIST_STREAMS_REQUEST))
    {
      request = (PLOGGER_LIST_STREAMS_REQUEST)Irp->AssociatedIrp.SystemBuffer;
      if (request->Version != WIN_API_LOGGER_CLIENT_VERSION)
        return STATUS_INVALID_PARAMETER;
      if (request->MaximumCount != 0 && request->MaximumCount < maximum_count)
        maximum_count = request->MaximumCount;
      after = request->AfterStreamId;
    }
  if (maximum_count == 0)
    return STATUS_BUFFER_TOO_SMALL;

  response = (PLOGGER_LIST_STREAMS_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
  RtlZeroMemory (response, output_length);

  for (;;)
    {
      LOGGER_PROCESS_STATE *next = NULL;

      KeAcquireSpinLock (&g_ProcessStatesLock, &old_irql);
      for (entry = g_ProcessStates.Flink; entry != &g_ProcessStates;
           entry = entry->Flink)
        {
          LOGGER_PROCESS_STATE *state
              = CONTAINING_RECORD (entry, LOGGER_PROCESS_STATE, ListEntry);
          if (state->DeletePending || state->StreamId <= after)
            continue;
          if (next == NULL || state->StreamId < next->StreamId)
            next = state;
        }
      if (next != NULL && count < maximum_count)
        {
          LoggerFillStreamInfo (&response->Streams[count], next);
          after = next->StreamId;
          ++count;
        }
      else
        more = next != NULL;
      KeReleaseSpinLock (&g_ProcessStatesLock, old_irql);
      if (next == NULL || count >= maximum_count)
        break;
    }

  response->Version = WIN_API_LOGGER_CLIENT_VERSION;
  response->Count = count;
  response->More = more ? 1u : 0u;
  Irp->IoStatus.Information
      = FIELD_OFFSET (LOGGER_LIST_STREAMS_RESPONSE, Streams)
        + (SIZE_T)count * sizeof (LOGGER_STREAM_INFO);
  return STATUS_SUCCESS;
}

static NTSTATUS
LoggerHandleReadStream (_In_ PIRP Irp, _In_ PIO_STACK_LOCATION Stack)
{
  PLOGGER_READ_STREAM_REQUEST request;
  PLOGGER_READ_STREAM_RESPONSE response;
  LOGGER_PROCESS_STATE *state;
  ULONG output_length = Stack->Parameters.DeviceIoControl.OutputBufferLength;
  ULONG header_size = FIELD_OFFSET (LOGGER_READ_STREAM_RESPONSE, Records);
  ULONG maximum_bytes;
  ULONG records;
  NTSTATUS status;
  LOGGER_MODULE_SNAPSHOT snapshot;

  if (Stack->Parameters.DeviceIoControl.InputBufferLength
          < sizeof (LOGGER_READ_STREAM_REQUEST)
      || output_length < header_size)
    return STATUS_BUFFER_TOO_SMALL;
  request = (PLOGGER_READ_STREAM_REQUEST)Irp->AssociatedIrp.SystemBuffer;
  if (request->Version != WIN_API_LOGGER_CLIENT_VERSION)
    return STATUS_INVALID_PARAMETER;

  maximum_bytes = output_length - header_size;
  if (request->MaximumBytes != 0 && request->MaximumBytes < maximum_bytes)
    maximum_bytes = request->MaximumBytes;
  state = LoggerFindStateByStreamId (request->StreamId);
  if (state == NULL)
    return STATUS_NOT_FOUND;
  LoggerInstallLoadedModules (state);

  response = (PLOGGER_READ_STREAM_RESPONSE)Irp->AssociatedIrp.SystemBuffer;
  RtlZeroMemory (response, output_length);
  RtlZeroMemory (&snapshot, sizeof (snapshot));
  if (LoggerQueueHasRecords (state, maximum_bytes))
    {
      status = LoggerBuildLoadedModuleSnapshot (state, &snapshot);
      if (!NT_SUCCESS (status))
        {
          LoggerDereferenceState (state);
          return status;
        }
    }
  ExAcquireResourceExclusiveLite (&state->QueueResource, TRUE);
  records = LoggerReadQueue (state, &snapshot,
                             (PUCHAR)response + header_size, maximum_bytes);
  response->Version = WIN_API_LOGGER_CLIENT_VERSION;
  response->RecordCount = records;
  response->BytesReturned = records * WIN_API_LOGGER_DRIVER_RECORD_SIZE;
  response->State = state->State;
  response->FailureReason = state->FailureReason;
  response->FailureStatus = state->FailureStatus;
  ExReleaseResourceLite (&state->QueueResource);
  Irp->IoStatus.Information = header_size + response->BytesReturned;
  LoggerFreeLoadedModuleSnapshot (&snapshot);
  LoggerDereferenceState (state);
  return STATUS_SUCCESS;
}

_Function_class_ (DRIVER_DISPATCH)
NTSTATUS
LoggerCreateClose (_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
  UNREFERENCED_PARAMETER (DeviceObject);
  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;
  IoCompleteRequest (Irp, IO_NO_INCREMENT);
  return STATUS_SUCCESS;
}

_Function_class_ (DRIVER_DISPATCH)
NTSTATUS
LoggerDeviceControl (_In_ PDEVICE_OBJECT DeviceObject, _In_ PIRP Irp)
{
  PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation (Irp);
  NTSTATUS status;

  UNREFERENCED_PARAMETER (DeviceObject);
  switch (stack->Parameters.DeviceIoControl.IoControlCode)
    {
    case WIN_API_LOGGER_IOCTL_ADD_FILTER:
      status = LoggerHandleAddFilter (Irp, stack);
      break;
    case WIN_API_LOGGER_IOCTL_RESET_FILTER:
      status = LoggerResetFilter ();
      break;
    case WIN_API_LOGGER_IOCTL_LIST_STREAMS:
      status = LoggerHandleListStreams (Irp, stack);
      break;
    case WIN_API_LOGGER_IOCTL_READ_STREAM:
      status = LoggerHandleReadStream (Irp, stack);
      break;
    default:
      status = STATUS_INVALID_DEVICE_REQUEST;
      break;
    }
  Irp->IoStatus.Status = status;
  if (!NT_SUCCESS (status))
    Irp->IoStatus.Information = 0;
  IoCompleteRequest (Irp, IO_NO_INCREMENT);
  return status;
}
