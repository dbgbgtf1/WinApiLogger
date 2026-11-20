#include <ntifs.h>
#include <stdint.h>
#include <wdmsec.h>

#include "../common/protocol.h"
#include "logger_internal.h"
#include "state.h"

#define LOGGER_WDM_DEVICE_NAME L"\\Device\\WinApiLogger"
#define LOGGER_WDM_SYMBOLIC_NAME L"\\DosDevices\\WinApiLogger"
#define LOGGER_SECURITY_SDDL L"D:P(A;;GA;;;SY)(A;;GA;;;BA)"

C_ASSERT (sizeof (LOGGER_CONTEXT) == WIN_API_LOGGER_CONTEXT_SIZE);
C_ASSERT (sizeof (LOGGER_QUEUE_HEADER) == WIN_API_LOGGER_QUEUE_HEADER_SIZE);
C_ASSERT (sizeof (LOGGER_LOG_RECORD) == WIN_API_LOGGER_LOG_RECORD_SIZE);
C_ASSERT (sizeof (LOGGER_DRIVER_RECORD) == WIN_API_LOGGER_DRIVER_RECORD_SIZE);
C_ASSERT (WIN_API_LOGGER_QUEUE_DATA_SIZE % WIN_API_LOGGER_LOG_RECORD_SIZE == 0);
C_ASSERT (WIN_API_LOGGER_QUEUE_CAPACITY
          == WIN_API_LOGGER_QUEUE_DATA_SIZE
                 / WIN_API_LOGGER_LOG_RECORD_SIZE);
C_ASSERT (WIN_API_LOGGER_PRIVATE_DATA_SIZE
          == WIN_API_LOGGER_CONTEXT_SIZE + WIN_API_LOGGER_QUEUE_SIZE);

static BOOLEAN g_CallbacksRegistered;
static BOOLEAN g_DeviceCreated;
static BOOLEAN g_SymbolicLinkCreated;

static VOID
LoggerUnwindInitialization (_In_ PDRIVER_OBJECT DriverObject)
{
  UNICODE_STRING symbolic_name;

  if (g_CallbacksRegistered)
    {
      (void)PsRemoveLoadImageNotifyRoutine (LoggerLoadImageNotify);
      (void)PsSetCreateProcessNotifyRoutineEx (LoggerCreateProcessNotify,
                                               TRUE);
      g_CallbacksRegistered = FALSE;
    }
  if (g_SymbolicLinkCreated)
    {
      RtlInitUnicodeString (&symbolic_name, LOGGER_WDM_SYMBOLIC_NAME);
      (void)IoDeleteSymbolicLink (&symbolic_name);
      g_SymbolicLinkCreated = FALSE;
    }
  if (g_DeviceCreated && DriverObject->DeviceObject != NULL)
    {
      IoDeleteDevice (DriverObject->DeviceObject);
      g_DeviceCreated = FALSE;
    }
}

_Function_class_ (DRIVER_UNLOAD)
static VOID
LoggerUnload (_In_ PDRIVER_OBJECT DriverObject)
{
  if (LoggerProcessHasLiveStates ())
    {
      /*
       * Windows cannot fail DriverUnload.  Unloading while a target still
       * executes a stub would leave dangling code and data, so fail closed.
       */
      KeBugCheckEx (DRIVER_UNLOADED_WITHOUT_CANCELLING_PENDING_OPERATIONS,
                    (ULONG_PTR)DriverObject, 1, 0, 0);
    }

  LoggerUnwindInitialization (DriverObject);
  LoggerProcessShutdown ();
  LoggerMemoryShutdown ();
}

NTSTATUS
DriverEntry (_In_ PDRIVER_OBJECT DriverObject,
             _In_ PUNICODE_STRING RegistryPath)
{
  NTSTATUS status;
  PDEVICE_OBJECT device_object = NULL;
  UNICODE_STRING device_name;
  UNICODE_STRING symbolic_name;
  UNICODE_STRING sddl;

  UNREFERENCED_PARAMETER (RegistryPath);

  DriverObject->MajorFunction[IRP_MJ_CREATE] = LoggerCreateClose;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = LoggerCreateClose;
  DriverObject->MajorFunction[IRP_MJ_CLEANUP] = LoggerCreateClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = LoggerDeviceControl;
  DriverObject->DriverUnload = LoggerUnload;

  status = LoggerMemoryInitialize ();
  if (!NT_SUCCESS (status))
    {
      LoggerUnload (DriverObject);
      return status;
    }
  status = LoggerProcessInitialize ();
  if (!NT_SUCCESS (status))
    {
      LoggerUnload (DriverObject);
      return status;
    }
  status = LoggerInitializeStubLayout ();
  if (!NT_SUCCESS (status))
    {
      LoggerUnload (DriverObject);
      return status;
    }

  RtlInitUnicodeString (&device_name, LOGGER_WDM_DEVICE_NAME);
  RtlInitUnicodeString (&symbolic_name, LOGGER_WDM_SYMBOLIC_NAME);
  RtlInitUnicodeString (&sddl, LOGGER_SECURITY_SDDL);

  status = IoCreateDeviceSecure (DriverObject, 0, &device_name,
                                 FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN,
                                 FALSE, &sddl, NULL, &device_object);
  if (!NT_SUCCESS (status))
    {
      LoggerUnload (DriverObject);
      return status;
    }
  g_DeviceCreated = TRUE;
  device_object->Flags |= DO_BUFFERED_IO;
  device_object->Flags &= ~DO_DEVICE_INITIALIZING;

  status = PsSetLoadImageNotifyRoutine (LoggerLoadImageNotify);
  if (!NT_SUCCESS (status))
    {
      LoggerUnload (DriverObject);
      return status;
    }
  status
      = PsSetCreateProcessNotifyRoutineEx (LoggerCreateProcessNotify, FALSE);
  if (!NT_SUCCESS (status))
    {
      (void)PsRemoveLoadImageNotifyRoutine (LoggerLoadImageNotify);
      LoggerUnload (DriverObject);
      return status;
    }
  g_CallbacksRegistered = TRUE;

  status = IoCreateSymbolicLink (&symbolic_name, &device_name);
  if (!NT_SUCCESS (status))
    {
      LoggerUnload (DriverObject);
      return status;
    }
  g_SymbolicLinkCreated = TRUE;

  DbgPrintEx (DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
              "WinApiLogger: loaded; %u exports, payload %u bytes\n",
              LOGGER_INSTALLABLE_EXPORT_COUNT, LOGGER_PAYLOAD_SIZE);
  return STATUS_SUCCESS;
}
