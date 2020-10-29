#include <ntddk.h>

#define DEVICE_SEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
#define DEVICE_REC CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)


UNICODE_STRING devname = RTL_CONSTANT_STRING(L"\\Device\\HookDriver");
UNICODE_STRING devlink = RTL_CONSTANT_STRING(L"\\DosDevices\\HOOKDRIVER");

UNICODE_STRING TargetDevice = RTL_CONSTANT_STRING(L"\\Device\\VCP0");

PDRIVER_OBJECT pDriver = NULL;
PDEVICE_OBJECT pDevice = NULL;
PFILE_OBJECT FileObject;

typedef NTSTATUS(*OLDIRPMJDEVICECONTROL)(IN PDEVICE_OBJECT, IN PIRP);
OLDIRPMJDEVICECONTROL WriteBackup;
OLDIRPMJDEVICECONTROL CreateBackup;
OLDIRPMJDEVICECONTROL CloseBackup;

BOOLEAN SendDataFlag = FALSE;
BOOLEAN SignalFlag = FALSE;
char *data = NULL;
int cnt = 0;

NTSTATUS DrvCreate(IN PDEVICE_OBJECT DriverObject, IN PIRP Irp)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Create()!\n");
	UNREFERENCED_PARAMETER(DriverObject);
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS DrvClose(IN PDEVICE_OBJECT DriverObject, IN PIRP Irp)
{
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Close()!\n");
	UNREFERENCED_PARAMETER(DriverObject);
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS Handlers(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(Irp);
	ULONG dwBufferSize = 0;
	ULONG i;
	char *buffer;
	Irp->IoStatus.Information = 0;
	Irp->IoStatus.Status = 0;

	switch (pStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		SendDataFlag = FALSE;
		return CreateBackup(DeviceObject, Irp);

	case IRP_MJ_CLOSE:
		SendDataFlag = TRUE;
		return CloseBackup(DeviceObject, Irp);

	case IRP_MJ_WRITE:

		dwBufferSize = pStack->Parameters.Write.Length;
		buffer = Irp->AssociatedIrp.SystemBuffer;

		if (SignalFlag) {
			for (i = 0; i < dwBufferSize; i++) {
				DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "%x ", buffer[i]);
				data[cnt++] = buffer[i];
			}
		}

		return WriteBackup(DeviceObject, Irp);
	default:
		break;
	}
	return STATUS_SUCCESS;
}

NTSTATUS HOOKING()
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "SEARCHING!\n");
	ntStatus = IoGetDeviceObjectPointer(&TargetDevice, FILE_READ_ATTRIBUTES, &FileObject, &pDevice);
	if (!NT_SUCCESS(ntStatus)) {
		return STATUS_UNSUCCESSFUL;
	}
	ObDereferenceObject(FileObject);
	
	pDriver = pDevice->DriverObject;
	if (pDriver) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "HOOKING SUCCESS!\n");
		WriteBackup = pDriver->MajorFunction[IRP_MJ_WRITE];
		CreateBackup = pDriver->MajorFunction[IRP_MJ_WRITE];
		CloseBackup = pDriver->MajorFunction[IRP_MJ_CLOSE];

		pDriver->MajorFunction[IRP_MJ_CREATE] = Handlers;
		pDriver->MajorFunction[IRP_MJ_WRITE] = Handlers;
		pDriver->MajorFunction[IRP_MJ_CLOSE] = Handlers;
	}
	else {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "HOOKING ERROR!\n");
	}
	return ntStatus;
}

NTSTATUS IoctlController(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(Irp);
	PVOID buffer = Irp->AssociatedIrp.SystemBuffer;

	switch (pStack->Parameters.DeviceIoControl.IoControlCode)
	{
	case DEVICE_SEND:
		cnt = 0;
		SendDataFlag = FALSE;
		SignalFlag = FALSE;
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		RtlZeroMemory(data, sizeof(data));
		break;

	case DEVICE_REC:
		SignalFlag = TRUE;
		if (SendDataFlag) {
			RtlCopyMemory(buffer, data, cnt);
			Irp->IoStatus.Information = cnt;
			Irp->IoStatus.Status = STATUS_SUCCESS;
		}
		break;

	default:
		Irp->IoStatus.Information = 0;
		Irp->IoStatus.Status = STATUS_SUCCESS;
		break;
	}
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return ntStatus;
}


void DrvUnload(IN PDRIVER_OBJECT DriverObejct)
{
	if (pDriver) {
		pDriver->MajorFunction[IRP_MJ_CREATE] = CreateBackup;
		pDriver->MajorFunction[IRP_MJ_CLOSE] = CloseBackup;
		pDriver->MajorFunction[IRP_MJ_WRITE] = WriteBackup;
	}
	ExFreePool(data);

	IoDeleteSymbolicLink(&devlink);
	IoDeleteDevice(DriverObejct->DeviceObject);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Unload!\n");
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(RegistryPath);
	NTSTATUS ntStatus;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "ENTRY!\n");
	PDEVICE_OBJECT devobject = 0;

	ntStatus = HOOKING();
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Driver Search error!\n");
		return STATUS_UNSUCCESSFUL;
	}

	DriverObject->DriverUnload = DrvUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = DrvCreate;
	DriverObject->MajorFunction[IRP_MJ_CLOSE] = DrvClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IoctlController;

	data = ExAllocatePool(NonPagedPool, sizeof(char) * 2048);

	IoCreateDevice(DriverObject, 0, &devname, FILE_DEVICE_UNKNOWN, 0, FALSE, &devobject);
	IoCreateSymbolicLink(&devlink, &devname);

	return STATUS_SUCCESS;
}
