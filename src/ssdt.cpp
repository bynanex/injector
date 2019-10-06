#include "injector.h"
#include "strings.h"
#include <stdio.h>
#include "util.h"

#define HOOK_SHADOW_SSDT	0	// Set to 1 if (a) not starting as a boot driver (Start >= 2) *and* (b) a shadow SSDT address or hook is desired.
								// If booting, either a manual IOCTL or a load image notify routine to find the shadow SSDT after win32k.sys loads is needed

typedef struct _KSERVICE_TABLE_DESCRIPTOR
{
	PLONG ServiceTable;		// KiServiceTable
	PULONG Count;
	SIZE_T Limit;			// KiServiceLimit
	PUCHAR ArgumentTable;	// KiArgumentTable
} KSERVICE_TABLE_DESCRIPTOR, *PKSERVICE_TABLE_DESCRIPTOR;

typedef struct _SERVICE_TABLE_ENTRY
{
	CHAR Name[64];			// Arbitrary limit, but it's good enough for "NtAccessCheckByTypeResultListAndAuditAlarmByHandle"
	PVOID Address;
} SERVICE_TABLE_ENTRY, *PSERVICE_TABLE_ENTRY;

extern DYNAMIC_DATA DynData;

extern ULONG_PTR NtoskrnlBase;
extern ULONG NtoskrnlSize;

static KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTable = { nullptr };
#if HOOK_SHADOW_SSDT
static KSERVICE_TABLE_DESCRIPTOR KeServiceDescriptorTableShadow = { nullptr };
#endif
static PSERVICE_TABLE_ENTRY SsdtEntries = nullptr;
#if HOOK_SHADOW_SSDT
static PSERVICE_TABLE_ENTRY SsdtEntriesShadow = nullptr;
#endif

static CONSTEXPR CONST UCHAR KiSystemServiceStartPattern[] = { 0x8B, 0xF8, 0xC1, 0xEF, 0x07, 0x83, 0xE7, 0x20, 0x25, 0xFF, 0x0F, 0x00, 0x00 };
static PUCHAR NtdllData = nullptr;

extern "C"
{
	static
	NTSTATUS
	FindKeServiceDescriptorTables(
		);

	static
	NTSTATUS
	FindSsdtNames(
		);

	static
	NTSTATUS
	FindSsdtAddresses(
		);
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, FindKeServiceDescriptorTables)
#pragma alloc_text(INIT, FindSsdtNames)
#pragma alloc_text(INIT, FindSsdtAddresses)
#pragma alloc_text(INIT, SsdtInitialize)
#pragma alloc_text(PAGE, SsdtUninitialize)
#endif

VOID
SsdtUninitialize(
	)
{
	PAGED_CODE();

	if (SsdtEntries != nullptr)
		ExFreePool(SsdtEntries);
#if HOOK_SHADOW_SSDT
	if (SsdtEntriesShadow != nullptr)
		ExFreePool(SsdtEntriesShadow);
#endif
}

KPROCESSOR_MODE
KeSetPreviousMode(
	_In_ KPROCESSOR_MODE ProcessorMode
	)
{
	// Get a pointer to the previous mode value
#ifdef _M_AMD64
	// mov rax, gs:188h, mov tmp, [rax + offset]
	KPROCESSOR_MODE *pPreviousMode = reinterpret_cast<KPROCESSOR_MODE*>(reinterpret_cast<PUCHAR>(__readgsqword(392)) + DynData.PreviousModeOffset);
#else
	// mov eax, large fs:124h, mov tmp, [eax + offset]
	KPROCESSOR_MODE *pPreviousMode = reinterpret_cast<KPROCESSOR_MODE*>(reinterpret_cast<PUCHAR>(__readfsdword(292)) + DynData.PreviousModeOffset);
#endif

	// Return the dereferenced old value and set the new one
	const KPROCESSOR_MODE OldPreviousMode = *pPreviousMode;
	*pPreviousMode = ProcessorMode;
	return OldPreviousMode;
}

static
NTSTATUS
FindKeServiceDescriptorTables(
	)
{
	PAGED_CODE();
	
	__try
	{
#ifndef _M_AMD64
		// x86: untested but this should still work
		UNICODE_STRING KeServiceDescriptorTableName = RTL_CONSTANT_STRING(L"KeServiceDescriptorTable");
		PVOID KeServiceDescriptorTableAddress = MmGetSystemRoutineAddress(&KeServiceDescriptorTableName);
		if (KeServiceDescriptorTableAddress == nullptr)
			return STATUS_NOT_FOUND;
#else
		// x64: Find KiSystemServiceStart by its signature
		constexpr const ULONG SignatureSize = sizeof(KiSystemServiceStartPattern);
		BOOLEAN Found = FALSE;
		ULONG KiSSSOffset;

		for (KiSSSOffset = 0; KiSSSOffset < NtoskrnlSize - SignatureSize; ++KiSSSOffset)
		{
			// No VM enter/exit here as it causes extreme slowdown
			if (memcmp((reinterpret_cast<PUCHAR>(NtoskrnlBase) + KiSSSOffset),
								KiSystemServiceStartPattern,
								SignatureSize) == 0)
			{
				Found = TRUE;
				break;
			}
		}
		if (!Found)
			return STATUS_NOT_FOUND;

		// Set new scan position: lea r10, KeServiceDescriptorTable
		const ULONG_PTR Address = NtoskrnlBase + KiSSSOffset + SignatureSize;
		LONG RelativeOffset = 0;
		if ((*reinterpret_cast<PUCHAR>(Address) == 0x4c) &&
			(*reinterpret_cast<PUCHAR>(Address + 1) == 0x8d) &&
			(*reinterpret_cast<PUCHAR>(Address + 2) == 0x15))
		{
			RelativeOffset = *reinterpret_cast<PLONG>(Address + 3);
		}
		const ULONG_PTR KeServiceDescriptorTableAddress = Address + RelativeOffset + 7;
		if (RelativeOffset == 0)
			return STATUS_NOT_FOUND;

#if HOOK_SHADOW_SSDT
		// Set new scan position: lea r11, KeServiceDescriptorTableShadow
		Address += 7;
		RelativeOffset = 0;
		if ((*reinterpret_cast<PUCHAR>(Address) == 0x4c) &&
			(*reinterpret_cast<PUCHAR>(Address + 1) == 0x8d) &&
			(*reinterpret_cast<PUCHAR>(Address + 2) == 0x1d))
		{
			RelativeOffset = *reinterpret_cast<PLONG>(Address + 3);
		}
		ULONG_PTR KeServiceDescriptorTableShadowAddress = Address + RelativeOffset + 7 + sizeof(KSERVICE_TABLE_DESCRIPTOR);
		if (RelativeOffset == 0)
			return STATUS_NOT_FOUND;

		// Found. Sanity check the addresses and copy the table
		if (KeServiceDescriptorTableAddress < reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) ||
			KeServiceDescriptorTableShadowAddress < reinterpret_cast<ULONG_PTR>(MmSystemRangeStart))
			return STATUS_NOT_FOUND;
#endif // HOOK_SHADOW_SSDT
#endif // M_AMD64

		RtlCopyMemory(&KeServiceDescriptorTable,
					reinterpret_cast<PVOID>(KeServiceDescriptorTableAddress),
					sizeof(KeServiceDescriptorTable));

		// Do some basic checks
		if (reinterpret_cast<ULONG_PTR>(KeServiceDescriptorTable.ServiceTable) < reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) ||
			KeServiceDescriptorTable.Limit == 0 ||
			KeServiceDescriptorTable.ArgumentTable < MmSystemRangeStart)
		{
			Printf("KeServiceDescriptorTable at 0x%p is NOT valid!\n",
				reinterpret_cast<PVOID>(KeServiceDescriptorTableAddress));
			return STATUS_NOT_FOUND;
		}

		Printf("KeServiceDescriptorTable: 0x%p\n", reinterpret_cast<PVOID>(KeServiceDescriptorTableAddress));
		Printf("ServiceTable: 0x%p, Limit: %llu, ArgumentTable: 0x%p\n",
			KeServiceDescriptorTable.ServiceTable, KeServiceDescriptorTable.Limit,
			reinterpret_cast<PVOID>(KeServiceDescriptorTable.ArgumentTable));

#ifdef _M_AMD64
#if HOOK_SHADOW_SSDT
		RtlCopyMemory(&KeServiceDescriptorTableShadow,
					reinterpret_cast<PVOID>(KeServiceDescriptorTableShadowAddress),
					sizeof(KeServiceDescriptorTableShadow));

		// Do some basic checks
		if (reinterpret_cast<ULONG_PTR>(KeServiceDescriptorTableShadow.ServiceTable) < reinterpret_cast<ULONG_PTR>(MmSystemRangeStart) ||
			KeServiceDescriptorTableShadow.Limit == 0 ||
			KeServiceDescriptorTableShadow.ArgumentTable < MmSystemRangeStart)
		{
			Printf("KeServiceDescriptorTableShadow at 0x%p is NOT valid!\n",
				reinterpret_cast<PVOID>(KeServiceDescriptorTableShadowAddress));
			return STATUS_NOT_FOUND;
		}

		Printf("KeServiceDescriptorTableShadow: 0x%p\n", reinterpret_cast<PVOID>(KeServiceDescriptorTableShadowAddress));
		Printf("ServiceTable: 0x%p, Limit: %llu, ArgumentTable: 0x%p\n",
			KeServiceDescriptorTableShadow.ServiceTable, KeServiceDescriptorTableShadow.Limit,
			reinterpret_cast<PVOID>(KeServiceDescriptorTableShadow.ArgumentTable));
#endif // HOOK_SHADOW_SSDT
#endif // _M_AMD64
	}
	__except (GetExceptionCode() == STATUS_ACCESS_VIOLATION
		? EXCEPTION_EXECUTE_HANDLER
		: EXCEPTION_CONTINUE_SEARCH)
	{
		return STATUS_ACCESS_VIOLATION;
	}
	return STATUS_SUCCESS;
}

static
NTSTATUS
FindSsdtNames(
	)
{
	PAGED_CODE();
	
	// Find and verify PE headers
	const PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(NtdllData);
	if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return STATUS_INVALID_IMAGE_NOT_MZ;
	const PIMAGE_NT_HEADERS NtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(NtdllData + DosHeader->e_lfanew);
	if (NtHeaders->Signature != IMAGE_NT_SIGNATURE)
		return STATUS_INVALID_IMAGE_FORMAT;

	// Get the export directory offset and size
	PIMAGE_DATA_DIRECTORY ImageDirectories;
	if (NtHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		ImageDirectories = reinterpret_cast<PIMAGE_NT_HEADERS64>(NtHeaders)->OptionalHeader.DataDirectory;
	else
		ImageDirectories = reinterpret_cast<PIMAGE_NT_HEADERS32>(NtHeaders)->OptionalHeader.DataDirectory;

	const ULONG ExportDirRva = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	const ULONG ExportDirSize = ImageDirectories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	const ULONG ExportDirOffset = RvaToOffset(NtHeaders, ExportDirRva);
	if (ExportDirOffset == 0)
		return STATUS_INVALID_IMAGE_FORMAT;

	// Read the export directory
	const PIMAGE_EXPORT_DIRECTORY ExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(NtdllData + ExportDirOffset);
	const ULONG AddressOfFunctionsOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfFunctions);
	const ULONG AddressOfNameOrdinalsOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfNameOrdinals);
	const ULONG AddressOfNamesOffset = RvaToOffset(NtHeaders, ExportDirectory->AddressOfNames);
	if (AddressOfFunctionsOffset == 0 || AddressOfNameOrdinalsOffset == 0 || AddressOfNamesOffset == 0)
		return STATUS_INVALID_IMAGE_FORMAT;

	const PULONG AddressOfFunctions = reinterpret_cast<PULONG>(NtdllData + AddressOfFunctionsOffset);
	const PUSHORT AddressOfNameOrdinals = reinterpret_cast<PUSHORT>(NtdllData + AddressOfNameOrdinalsOffset);
	const PULONG AddressOfNames = reinterpret_cast<PULONG>(NtdllData + AddressOfNamesOffset);

	// Iterate over the exported functions
	for (ULONG i = 0; i < ExportDirectory->NumberOfNames; ++i)
	{
		const ULONG NameOffset = RvaToOffset(NtHeaders, AddressOfNames[i]);
		if (NameOffset == 0)
			continue;

		const PCSTR FunctionName = reinterpret_cast<PSTR>(NtdllData + NameOffset);
		const ULONG FunctionRva = AddressOfFunctions[AddressOfNameOrdinals[i]];
		if (FunctionRva >= ExportDirRva && FunctionRva < ExportDirRva + ExportDirSize)
			continue; // Ignore forwarded exports

		if (FunctionName[0] == 'N' && FunctionName[1] == 't' && // We're looking for NtXxx, but not NtdllXxx functions
			(!(FunctionName[2] == 'd' && FunctionName[3] == 'l' && FunctionName[4] == 'l')))
		{
			const ULONG ExportOffset = RvaToOffset(NtHeaders, FunctionRva);
			if (ExportOffset != 0)
			{
				ULONG ServiceId = *reinterpret_cast<PULONG>(NtdllData + ExportOffset + 4);
				if (ServiceId >= KeServiceDescriptorTable.Limit)
					continue;
				strncpy_s(SsdtEntries[ServiceId].Name, sizeof(SsdtEntries[ServiceId].Name), FunctionName, sizeof(SsdtEntries[ServiceId].Name) - sizeof(CHAR));
			}
		}
	}
	return STATUS_SUCCESS;
}

static
NTSTATUS
FindSsdtAddresses(
	)
{
	PAGED_CODE();

	// For each syscall in the SSDT, get its kernel address
	for (ULONG ServiceId = 0; ServiceId < KeServiceDescriptorTable.Limit; ++ServiceId)
	{
#ifndef _M_AMD64
		SsdtEntries[ServiceId].Address = reinterpret_cast<PVOID>(
										KeServiceDescriptorTable.ServiceTable[ServiceId]);
#else
		SsdtEntries[ServiceId].Address = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(
										KeServiceDescriptorTable.ServiceTable) +
										(KeServiceDescriptorTable.ServiceTable[ServiceId] >> 4));
#endif
	}

#ifdef _M_AMD64
#if HOOK_SHADOW_SSDT
	// To be able to access the win32k.sys shadow SSDT, we need to be in the address space of a GUI process
	PEPROCESS Process;
	WCHAR CsrssExe[EncryptedCsrssString.Length];
	DecryptString(EncryptedCsrssString, CsrssExe);
	UNICODE_STRING ProcessName = { EncryptedCsrssString.Length - sizeof(WCHAR), EncryptedCsrssString.Length, CsrssExe };
	const NTSTATUS Status = OpenSessionProcess(&Process,
												&ProcessName,
												1,
												FALSE);
	RtlSecureZeroMemory(CsrssExe, EncryptedCsrssString.Length);
	if (!NT_SUCCESS(Status))
		return Status;

	KAPC_STATE ApcState;
	KeStackAttachProcess(Process, &ApcState);

	for (ULONG ServiceId = 0; ServiceId < KeServiceDescriptorTableShadow.Limit; ++ServiceId)
	{
		SsdtEntriesShadow[ServiceId].Address = reinterpret_cast<PVOID>(reinterpret_cast<ULONG_PTR>(
			KeServiceDescriptorTableShadow.ServiceTable) +
			(KeServiceDescriptorTableShadow.ServiceTable[ServiceId] >> 4));

		ULONG_PTR Address = reinterpret_cast<ULONG_PTR>(SsdtEntriesShadow[ServiceId].Address);
		if (*reinterpret_cast<PUCHAR>(Address) == 0xFF &&
			*reinterpret_cast<PUCHAR>(Address + 1) == 0x25)
		{
			// This is a jmp to the IAT...
			LONG RelativeOffset = *reinterpret_cast<PLONG>(Address + 2);
			Address = Address + RelativeOffset + 6;

			// ...which in turn points to the real address. Good job Windows 10
			SsdtEntriesShadow[ServiceId].Address = *reinterpret_cast<PVOID*>(Address);
		}
	}

	KeUnstackDetachProcess(&ApcState);

	ObfDereferenceObject(Process);
#endif // HOOK_SHADOW_SSDT
#endif // _M_AMD64

	return STATUS_SUCCESS;
}

PVOID
GetSyscallAddress(
	_In_ PCSTR FunctionName
	)
{
	for (ULONG ServiceId = 0; ServiceId < KeServiceDescriptorTable.Limit; ++ServiceId)
	{
		if (strcmp(FunctionName, SsdtEntries[ServiceId].Name) == 0)
		{
			return SsdtEntries[ServiceId].Address;
		}
	}
	return nullptr;
}

NTSTATUS
SsdtInitialize(
	)
{
	PAGED_CODE();

	WCHAR NtdllPath[decltype(EncryptedNtdllPathString)::Length];
	UNICODE_STRING NtdllFilename = { decltype(EncryptedNtdllPathString)::Length - sizeof(WCHAR), decltype(EncryptedNtdllPathString)::Length, NtdllPath };
	SIZE_T NtdllSize = 0;

	// LocatePspNotifyEnableMask() should have already found these for us
	NT_ASSERT(NtoskrnlBase != 0);
	NT_ASSERT(NtoskrnlSize != 0);

	// Find the SSDT
	RtlZeroMemory(&KeServiceDescriptorTable, sizeof(KeServiceDescriptorTable));
#if HOOK_SHADOW_SSDT
	RtlZeroMemory(&KeServiceDescriptorTableShadow, sizeof(KeServiceDescriptorTableShadow));
#endif
	NTSTATUS Status = FindKeServiceDescriptorTables();
	if (!NT_SUCCESS(Status))
		goto finished;

	// Read ntdll.dll from disk
	DecryptString(EncryptedNtdllPathString, NtdllPath);
	Status = RtlReadFileToBytes(&NtdllFilename,
								&NtdllData,
								&NtdllSize);
	RtlSecureZeroMemory(NtdllFilename.Buffer, decltype(EncryptedNtdllPathString)::Length);
	if (!NT_SUCCESS(Status))
		goto finished;

	// Allocate space for the SSDT entries (~3.5 MB) and the win32k SSDT entries (~7 MB)
	SsdtEntries = static_cast<PSERVICE_TABLE_ENTRY>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
							sizeof(SERVICE_TABLE_ENTRY) * KeServiceDescriptorTable.Limit,
							GetPoolTag()));
#if HOOK_SHADOW_SSDT
	SsdtEntriesShadow = static_cast<PSERVICE_TABLE_ENTRY>(
		ExAllocatePoolWithTag(NonPagedPoolNx,
							sizeof(SERVICE_TABLE_ENTRY) * KeServiceDescriptorTableShadow.Limit,
							GetPoolTag()));
#endif
	if (SsdtEntries == nullptr
#if HOOK_SHADOW_SSDT
		|| SsdtEntriesShadow == nullptr
#endif
		)
	{
		Status = STATUS_NO_MEMORY;
		goto finished;
	}
	RtlZeroMemory(SsdtEntries, sizeof(SERVICE_TABLE_ENTRY) * KeServiceDescriptorTable.Limit);
#if HOOK_SHADOW_SSDT
	RtlZeroMemory(SsdtEntriesShadow, sizeof(SERVICE_TABLE_ENTRY) * KeServiceDescriptorTableShadow.Limit);
#endif

	// Convert the table to entries in [Name, Address] format
	Status = FindSsdtNames();
	if (!NT_SUCCESS(Status))
		goto finished;
	Status = FindSsdtAddresses();
	//if (!NT_SUCCESS(Status))
	//	goto finished; // We are going there regardless. Obviously !!!UNCOMMENT THIS!!! if any code is added below

finished:
	if (NtdllData != nullptr)
	{
		RtlSecureZeroMemory(NtdllData, NtdllSize);
		ExFreePool(NtdllData);
	}
	if (!NT_SUCCESS(Status))
	{
		if (SsdtEntries != nullptr)
			ExFreePool(SsdtEntries);
#if HOOK_SHADOW_SSDT
		if (SsdtEntriesShadow != nullptr)
			ExFreePool(SsdtEntriesShadow);
#endif
	}
	return Status;
}
