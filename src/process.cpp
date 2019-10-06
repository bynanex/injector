#include "injector.h"
#include "util.h"

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, CreateProcessNotifyRoutine)
#pragma alloc_text(PAGE, OpenSessionProcess)
#pragma alloc_text(PAGE, CancelAllProcessWaits)
#endif

static KEVENT ProcessCreatedEvent;
static PUNICODE_STRING NotifyProcessName = nullptr;
static PEPROCESS NotifyProcess = nullptr;

VOID
CreateProcessNotifyRoutine(
	_Inout_ PEPROCESS Process,
	_In_ HANDLE ProcessId,
	_Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo
	)
{
	PAGED_CODE();

	UNREFERENCED_PARAMETER(ProcessId);

	if (CreateInfo == nullptr || CreateInfo->ImageFileName == nullptr ||
		!RtlUnicodeStringEndsIn(CreateInfo->ImageFileName, NotifyProcessName))
		return;

	// Reference the process object and signal the waiting thread
	ObfReferenceObjectWithTag(Process, GetPoolTag());
	NotifyProcess = Process;
	KeSetEvent(&ProcessCreatedEvent,
				IO_NO_INCREMENT,
				FALSE);
}

NTSTATUS
OpenSessionProcess(
	_Out_ PEPROCESS *Process,
	_In_ PUNICODE_STRING ProcessName,
	_In_ ULONG SessionId,
	_In_ BOOLEAN Wait
	)
{
	PAGED_CODE();

	// First try to find the process by enumerating existing ones
	ULONG Size;
	if (NtQuerySystemInformation(SystemProcessInformation, nullptr, 0, &Size) != STATUS_INFO_LENGTH_MISMATCH)
		return STATUS_UNSUCCESSFUL;
	const PSYSTEM_PROCESS_INFORMATION SystemProcessInfo =
		static_cast<PSYSTEM_PROCESS_INFORMATION>(ExAllocatePoolWithTag(NonPagedPoolNx, 2 * Size, GetPoolTag()));
	if (SystemProcessInfo == nullptr)
		return STATUS_NO_MEMORY;
	NTSTATUS Status = NtQuerySystemInformation(SystemProcessInformation,
												SystemProcessInfo,
												2 * Size,
												nullptr);
	if (!NT_SUCCESS(Status))
	{
		ExFreePool(SystemProcessInfo);
		return Status;
	}

	PSYSTEM_PROCESS_INFORMATION Entry = SystemProcessInfo;
	Status = STATUS_NOT_FOUND;

	while (true)
	{
		if (Entry->ImageName.Buffer != nullptr &&
			RtlCompareUnicodeString(&Entry->ImageName, ProcessName, TRUE) == 0)
		{
			Status = PsLookupProcessByProcessId(Entry->UniqueProcessId, Process);
			if (NT_SUCCESS(Status))
			{
				if (PsGetProcessSessionIdEx(*Process) == SessionId)
					break;
				
				ObfDereferenceObject(*Process);
			}
		}

		if (Entry->NextEntryOffset == 0)
			break;

		Entry = reinterpret_cast<PSYSTEM_PROCESS_INFORMATION>(reinterpret_cast<ULONG_PTR>(Entry) +
																Entry->NextEntryOffset);
	}
	ExFreePool(SystemProcessInfo);

	if (Status == STATUS_NOT_FOUND && Wait)
	{
		// Process doesn't exist yet, and a blocking wait was requested
		Printf("Waiting for process %wZ...\n", ProcessName);
		NotifyProcessName = ProcessName;
		NotifyProcess = nullptr;

		KeInitializeEvent(&ProcessCreatedEvent,
						NotificationEvent, // This is not intended to be thread safe
						FALSE);

		PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, FALSE);

		KeWaitForSingleObject(&ProcessCreatedEvent,
							Executive,
							KernelMode,
							FALSE,
							nullptr);

		PsSetCreateProcessNotifyRoutineEx(CreateProcessNotifyRoutine, TRUE);

		if (NotifyProcess == nullptr)
		{
			// This can only happen if the wait was cancelled by the driver unloading
			Status = STATUS_CANCELLED;
			*Process = nullptr;
		}
		else
		{
			Status = STATUS_SUCCESS;
			*Process = NotifyProcess;

			// Give the loader some time in order to prevent ResolveImports() from failing in the newly created process
			RtlSleep(50);
		}
	}

	// Reset these values to signal there are no waiters, to ensure consistent behaviour across multiple calls (note: I didn't say multiple *simultaneous* calls...)
	NotifyProcessName = nullptr;
	NotifyProcess = nullptr;

	return Status;
}

// This will set the 'process created' event even though no process was created. This will unblock all threads that are currently waiting in
// OpenSessionProcess() and make them return a failure code. If this is not called *and* there is a thread waiting for a process to spawn
// at the time of unload, the next process to start or exit (any process) will BSOD the system due to a non-existing notify routine being called.
VOID
CancelAllProcessWaits(
	)
{
	PAGED_CODE();

	if (NotifyProcessName == nullptr)
	{
		// Nothing to do (no waiters). The driver may be unloading before the kernel event was even initialized, so don't touch it.
		return;
	}

	NotifyProcess = nullptr; // Signal that waiters should abort
	KeSetEvent(&ProcessCreatedEvent,
				IO_NO_INCREMENT,
				FALSE);

	// Waiters are responsible for unregistering their own notification routines.
}
