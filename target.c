#include <ntddk.h>
#define IOCTL_SIMPLE_CONTROL CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _DEVICE_EXTENSION {
	PDEVICE_OBJECT NextDeviceObject;
	UNICODE_STRING UnicodeString;
}DEVICE_EXTENSION, *PDEVICE_EXTENSION;

PDEVICE_OBJECT DevObj = NULL;
PDEVICE_OBJECT NextDevice = NULL;
UNICODE_STRING TargetDevice = RTL_CONSTANT_STRING(L"\\Device\\00000053");
UNICODE_STRING DeviceName = RTL_CONSTANT_STRING(L"\\Device\\HOOKING_TARGET");
UNICODE_STRING SymbolicName = RTL_CONSTANT_STRING(L"\\??\\HOOKING_TARGET");
PVOID buffer;

VOID _DriverUnload(IN PDRIVER_OBJECT DriverObject) {

	PDEVICE_OBJECT DeviceObject = DriverObject->DeviceObject;
	NTSTATUS ntStatus = STATUS_SUCCESS;

	if (DevObj != NULL) {
		IoDetachDevice(((PDEVICE_EXTENSION)DeviceObject->DeviceExtension)->NextDeviceObject);
		ntStatus = IoDeleteSymbolicLink(&SymbolicName);
		if (!NT_SUCCESS(ntStatus)) {
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "DELETE SYM ERROR!\n");
		}
		IoDeleteDevice(DevObj);
	}
	else
	{
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "DRIVER UNLOADING ERROR!\n");
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "DRIVER UNLOADING!\n");

}

NTSTATUS _AttachingDriver(IN PDRIVER_OBJECT DriverObject)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	ntStatus = IoCreateDevice(
		DriverObject,
		sizeof(DEVICE_EXTENSION),
		&DeviceName,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DevObj
	);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Create Device Fail !\n");
		//IoDeleteDevice(DevObj);
		return ntStatus;
	}
	ntStatus = IoCreateSymbolicLink(&SymbolicName, &DeviceName);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Create Symbolic Fail !\n");
		//IoDeleteDevice(DevObj);
		return ntStatus;
	}

	DevObj->Flags |= DO_BUFFERED_IO | DRVO_LEGACY_RESOURCES;
	DevObj->Flags &= ~DO_DEVICE_INITIALIZING;

	RtlZeroMemory(DevObj->DeviceExtension, sizeof(DEVICE_EXTENSION));
	ntStatus = IoAttachDevice(DevObj, &TargetDevice, &((PDEVICE_EXTENSION)DevObj->DeviceExtension)->NextDeviceObject);

	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Attaching Device Fail !\n");
		IoDeleteSymbolicLink(&SymbolicName);
		IoDeleteDevice(DevObj);
		return ntStatus;
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Attaching Driver Succsess !\n");
	return ntStatus;
}

NTSTATUS DispatchMjFunction(PDEVICE_OBJECT DeviceObject, PIRP irp)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	PIO_STACK_LOCATION pStack = IoGetCurrentIrpStackLocation(irp);
	switch (pStack->MajorFunction)
	{
	case IRP_MJ_CREATE:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Create() \n");
		break;
	case IRP_MJ_CLEANUP:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "CleanUp() \n");
		break;
	case IRP_MJ_CLOSE:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Close() \n");
		break;
	case IRP_MJ_FILE_SYSTEM_CONTROL:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "FILE SYSTEM CONTROL \n");
		break;
	case IRP_MJ_FLUSH_BUFFERS:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "FLUSH_BUFFERS() \n");
		break;
	default:
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "IRP_MJ_XXX : %d \n", pStack->MajorFunction);
		break;
	}
	IoCopyCurrentIrpStackLocationToNext(irp);
	irp->IoStatus.Status = STATUS_SUCCESS;
	//IoCompleteRequest(irp, IO_NO_INCREMENT);
	ntStatus = IoCallDriver(((PDEVICE_EXTENSION)(DevObj->DeviceExtension))->NextDeviceObject, irp);
	return ntStatus;
}

NTSTATUS DispatchWrite(PDEVICE_OBJECT DeviceObject, PIRP irp) {
	NTSTATUS ntStatus = STATUS_SUCCESS;

	buffer = irp->AssociatedIrp.SystemBuffer;
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "%s \n", buffer);
	IoCopyCurrentIrpStackLocationToNext(irp);
	ntStatus = IoCallDriver(((PDEVICE_EXTENSION)(DevObj->DeviceExtension))->NextDeviceObject, irp);
	return ntStatus;
}
//NTSTATUS PowerDispatch
//(
//	IN PDEVICE_OBJECT DeviceObject,
//	IN PIRP Irp
//)
//{
//	PDEVICE_EXTENSION        deviceExtension;
//	NTSTATUS returnStatus;
//	PDEVICE_OBJECT NextLayerDeviceObject;
//
//	deviceExtension = DeviceObject->DeviceExtension;
//	NextLayerDeviceObject = deviceExtension->NextDeviceObject;
//
//	// 또 다른 Power IRP명령어를 받을 수 있다는 사실을 Power Manager에게 알립니다
//	PoStartNextPowerIrp(Irp);
//
//	// Power IRP의 소유권을 다음 계층을 위해서 포기합니다
//	IoSkipCurrentIrpStackLocation(Irp);
//
//	// PoCallDriver를 사용하는것을 유의하세요
//	returnStatus = PoCallDriver(NextLayerDeviceObject, Irp);
//	DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "POWER Dispatch!\n");
//	return returnStatus;
//}

NTSTATUS DeviceIoControl
(
	IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp
)
{
	PIO_STACK_LOCATION pStack;
	NTSTATUS returnStatus = STATUS_UNSUCCESSFUL;
	ULONG ulIoControlCode;
	PVOID pInputBuffer, pOutputBuffer;
	ULONG ulInputBufferLength, ulOutputBufferLength;
	ULONG_PTR Information;

	/*
	잘못된 파라미터가 전달되었는지를 확인하는 목적으로 필요한 변수값들을 모두 가져옵니다
	*/
	pStack = IoGetCurrentIrpStackLocation(Irp);
	ulInputBufferLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
	ulOutputBufferLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;
	ulIoControlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
	pInputBuffer = pOutputBuffer = Irp->AssociatedIrp.SystemBuffer;

	switch (ulIoControlCode)
	{
	case IOCTL_SIMPLE_CONTROL: // 응용프로그램이 사용한 IOControlCode를 확인합니다
		returnStatus = STATUS_SUCCESS; // 지금은 별다른 처리없이 성공으로 완료합니다
		Information = 0;
		break;

	default:
		returnStatus = STATUS_SUCCESS;
		Information = 0;
		break;
	}

	//IoCopyCurrentIrpStackLocationToNext(Irp);
	Irp->IoStatus.Information = Information;
	Irp->IoStatus.Status = returnStatus;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	//return IoCallDriver(((PDEVICE_EXTENSION)(DevObj->DeviceExtension))->NextDeviceObject, Irp);
	return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath)
{
	NTSTATUS ntStatus = STATUS_SUCCESS;
	int i;
	DriverObject->DriverUnload = _DriverUnload;
	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION; i++) {
		DriverObject->MajorFunction[i] = DispatchMjFunction;
	}
	//DriverObject->MajorFunction[IRP_MJ_WRITE] = DispatchWrite;
	//DriverObject->MajorFunction[IRP_MJ_POWER] = PowerDispatch;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DeviceIoControl;

	ntStatus = _AttachingDriver(DriverObject);
	if (!NT_SUCCESS(ntStatus)) {
		DbgPrintEx(DPFLTR_IHVDRIVER_ID, 0, "Attaching Fail !!\n");
		return ntStatus;
	}

	return ntStatus;
}
