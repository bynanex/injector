#include "injector.h"
#include "strings.h"
#include "util.h"

ULONG_PTR NtoskrnlBase = 0;
ULONG NtoskrnlSize = 0;

// rsh, AND, etc etc -> mov rax, <address we want>
static CONSTEXPR const UCHAR MiGetPteAddressStartPattern[] = { 0x48, 0xC1, 0xE9, 0x09, 0x48, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00, 0x48, 0x23, 0xC8, 0x48, 0xB8 };
static CONSTEXPR const UCHAR MiGetPdeAddressStartPattern[] = { 0x48, 0xC1, 0xE9, 0x12, 0x81, 0xE1, 0xF8, 0xFF, 0xFF, 0x3F, 0x48, 0xB8 };

// add rax, rcx, retn. These bytes are actually necessary because there are still duplicates when only matching on the above, even including the address itself
static CONSTEXPR const UCHAR CommonReturnPattern[] = { 0x48, 0x03, 0xC1, 0xC3 };

extern "C"
{
	DECLSPEC_NOINLINE
	static
	ULONG_PTR
	FindPattern(
		_In_ ULONG_PTR Base,
		_In_ ULONG Size,
		_In_ const UCHAR *Pattern,
		_In_ ULONG PatternLength
		);

	DECLSPEC_NOINLINE
	static
	ULONG_PTR
	BacktrackToFunctionStart(
		_In_ PUCHAR StartAddress,
		_In_ PUCHAR LowerBound
		);

	static
	NTSTATUS
	FindNtoskrnl(
		_Out_ PULONG_PTR KernelBase,
		_Out_ PULONG KernelSize
		);
}

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, FindPattern)
#pragma alloc_text(INIT, BacktrackToFunctionStart)
#pragma alloc_text(INIT, FindNtoskrnl)
#pragma alloc_text(INIT, LocatePageTables)
#pragma alloc_text(INIT, LocatePspNotifyEnableMask)
#pragma alloc_text(INIT, LocateMmUnloadedDrivers)
#pragma alloc_text(INIT, LocatePiDDBCacheTable)
#endif

DECLSPEC_NOINLINE
static
ULONG_PTR
FindPattern(
	_In_ ULONG_PTR Base,
	_In_ ULONG Size,
	_In_ const UCHAR *Pattern,
	_In_ ULONG PatternLength
	)
{
	for (PUCHAR Address = reinterpret_cast<PUCHAR>(Base);
		Address < reinterpret_cast<PUCHAR>(Base + Size - PatternLength);
		++Address)
	{
		ULONG i;
		for (i = 0; i < PatternLength; ++i)
		{
			if (Pattern[i] != 0xCC && (*(Address + i) != Pattern[i]))
				break;
		}

		if (i == PatternLength)
			return reinterpret_cast<ULONG_PTR>(Address);
	}
	return 0;
}

DECLSPEC_NOINLINE
static
ULONG_PTR
BacktrackToFunctionStart(
	_In_ PUCHAR StartAddress,
	_In_ PUCHAR LowerBound
	)
{
	NT_ASSERT(StartAddress > LowerBound);

	PUCHAR Address;
	BOOLEAN Found = FALSE;
	for (Address = StartAddress; Address >= LowerBound; --Address)
	{
		if ((*(Address - 1) == 0xCC ||										// Previous byte is int 3 padding, or
			(*(Address - 2) == 0x90 && *(Address - 1) == 0x90) ||			// Previous 2 bytes are nop padding, or
			(*(Address - 4) == 0x00 && *(Address - 3) == 0x00 &&			// Previous 4+ bytes are 00 padding (rare, only happens at start of a section), or
				*(Address - 2) == 0x00 && *(Address - 1) == 0x00) ||
			(*(Address - 1) == 0xC3 && *(Address - 3) != 0x8D)				// Previous byte is 'ret', or
#ifdef _M_IX86
			|| (*(Address - 3) == 0xC2 && *(Address - 1) == 0x00)			// Previous 3 bytes are 'ret XX' (x86)
#endif
			)
			&&																// *and*
			(*Address == 0x40 || *Address == 0x55 ||						// Current byte is either 'push [e|r]bp', 'mov REG, XX' or 'sub REG, XX'
				(Address < StartAddress && *Address == 0x44 && *(Address + 1) == 0x89) ||
				(Address < StartAddress && *Address == 0x48 && *(Address + 1) == 0x83) ||
				(Address < StartAddress && *Address == 0x48 && *(Address + 1) == 0x89) ||
				(Address < StartAddress && *Address == 0x48 && *(Address + 1) == 0x8B) ||
				(Address < StartAddress && *Address == 0x49 && *(Address + 1) == 0x89) ||
				(Address < StartAddress && *Address == 0x4C && *(Address + 1) == 0x8B)))
		{
			Found = TRUE;
			break;
		}
	}

	return Found ? reinterpret_cast<ULONG_PTR>(Address) : 0;
}

static
NTSTATUS
FindNtoskrnl(
	_Out_ PULONG_PTR KernelBase,
	_Out_ PULONG KernelSize
	)
{
	PAGED_CODE();

	*KernelBase = 0;
	*KernelSize = 0;

	NTSTATUS Status;
	ULONG Size;
	if ((Status = NtQuerySystemInformation(SystemModuleInformation, nullptr, 0, &Size)) != STATUS_INFO_LENGTH_MISMATCH)
		return Status;
	const PRTL_PROCESS_MODULES Modules =
		static_cast<PRTL_PROCESS_MODULES>(ExAllocatePoolWithTag(NonPagedPoolNx, 2 * Size, GetPoolTag()));
	if (Modules == nullptr)
		return STATUS_NO_MEMORY;

	Status = NtQuerySystemInformation(SystemModuleInformation,
										Modules,
										2 * Size,
										&Size);
	if (NT_SUCCESS(Status))
	{
		*KernelBase = reinterpret_cast<ULONG_PTR>(Modules->Modules[0].ImageBase);
		*KernelSize = Modules->Modules[0].ImageSize;
	}

	ExFreePool(Modules);

	return Status;
}

// Get relocated PDE and PTE bases for Windows 10 RS1+. This was previously a ghetto disassembler of MiGetPhysicalAddress, but that method no
// longer works reliably as of RS4*, and it was always a mess anyway because it needed adjustments every time a major update was released.
// This is an improved version that is intended to work without having to add checks for different kernel versions. It relies on the fact that
// MiGetPdeAddress and MiGetPteAddress have byte patterns that do not ever seem to change (they are very short functions, so this is not so strange).
//
// *I think this is also true for RS3 after the KVA shadowing patch, so it is more likely a result of that than something in RS4.
// **For reference, the actual table relocation happens (VERY early) in MxRelocatePageTables
NTSTATUS
LocatePageTables(
	_Inout_ PDYNAMIC_DATA Data
	)
{
	PAGED_CODE();

	Data->DYN_PDE_BASE = 0;
	Data->DYN_PTE_BASE = 0;

	const PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(reinterpret_cast<PVOID>(NtoskrnlBase), NtoskrnlSize);
	if (NtHeaders == nullptr)
		return STATUS_INVALID_IMAGE_FORMAT;

	// MiGetPteAddress and MiGetPdeAddress are both in .text, which is convenient as it is (a) the first section, and (b) guaranteed to be nonpaged
	const PIMAGE_SECTION_HEADER TextSection = IMAGE_FIRST_SECTION(NtHeaders);

	// Do the search. Both patterns should have exactly one match, otherwise reject the data.
	for (PUCHAR Address = reinterpret_cast<PUCHAR>(NtoskrnlBase + TextSection->VirtualAddress);
		reinterpret_cast<ULONG_PTR>(Address) < NtoskrnlBase + TextSection->Misc.VirtualSize;
		Address += 2) // I thought the addresses would be pointer-aligned but this is apparently not the case, so the most we can assume is that (address & 1) == 0
	{
		if (memcmp(Address, MiGetPdeAddressStartPattern, sizeof(MiGetPdeAddressStartPattern)) == 0 &&
			memcmp(Address + sizeof(MiGetPdeAddressStartPattern) + sizeof(PVOID), CommonReturnPattern, sizeof(CommonReturnPattern)) == 0)
		{
			if (Data->DYN_PDE_BASE != 0)
			{
				Printf("Found one or more duplicate matches for MiGetPdeAddress at 0x%p! Not trusting found data.\n", Address);
				Data->DYN_PDE_BASE = 0xFFFFFFFF;
			}
			else
			{
				Printf("Found MiGetPdeAddress at 0x%p\n", Address);
				Data->DYN_PDE_BASE = *reinterpret_cast<PULONG_PTR>(Address + sizeof(MiGetPdeAddressStartPattern));
			}
		}
		else if (memcmp(Address, MiGetPteAddressStartPattern, sizeof(MiGetPteAddressStartPattern)) == 0 &&
			memcmp(Address + sizeof(MiGetPteAddressStartPattern) + sizeof(PVOID), CommonReturnPattern, sizeof(CommonReturnPattern)) == 0)
		{
			if (Data->DYN_PTE_BASE != 0)
			{
				Printf("Found one or more duplicate matches for MiGetPteAddress at 0x%p! Not trusting found data.\n", Address);
				Data->DYN_PTE_BASE = 0xFFFFFFFF;
			}
			else
			{
				Printf("Found MiGetPteAddress at 0x%p\n", Address);
				Data->DYN_PTE_BASE = *reinterpret_cast<PULONG_PTR>(Address + sizeof(MiGetPteAddressStartPattern));
			}
		}

		if (Data->DYN_PDE_BASE != 0 && Data->DYN_PTE_BASE != 0)
			break;
	}

	if (Data->DYN_PDE_BASE == 0xFFFFFFFF || Data->DYN_PTE_BASE == 0xFFFFFFFF)
		Data->DYN_PDE_BASE = Data->DYN_PTE_BASE = 0;

	if (Data->DYN_PDE_BASE == 0 || Data->DYN_PTE_BASE == 0)
		Printf("Failed to find PDE_BASE and PTE_BASE.\n");
	else
		Printf("PDE_BASE: 0x%p, PTE_BASE: 0x%p\n",
			reinterpret_cast<PVOID>(Data->DYN_PDE_BASE),
			reinterpret_cast<PVOID>(Data->DYN_PTE_BASE));

	return Data->DYN_PTE_BASE != 0 && Data->DYN_PDE_BASE != 0
		? STATUS_SUCCESS
		: STATUS_NOT_FOUND;
}

NTSTATUS
LocatePspNotifyEnableMask(
	_Inout_ PDYNAMIC_DATA Data
	)
{
	PAGED_CODE();

	Data->pPspNotifyEnableMask = nullptr;

	// Find the kernel image base and size. The SSDT finder needs these too, but since we are called first we get to do the honours.
	const NTSTATUS Status = FindNtoskrnl(&NtoskrnlBase, &NtoskrnlSize);
	if (!NT_SUCCESS(Status))
		return Status;

	// Get the address of PsSetCreateThreadNotifyRoutine (hereafter referred to as PsSetThreadNR, as opposed to Ps>>>p<<<SetThreadNotifyRoutine).
	// The reason for not using MmGetSystemRoutineAddress (or a static import) is that Driver Verifier reroutes PsSetThreadNR along
	// various paths to check stuff. We are not interested in calling the function, only its (real) address. So use GetProcedureAddress
	CHAR PsSetCreateThreadNotifyRoutineBuffer[decltype(EncryptedPsSetCreateThreadNotifyRoutineString)::Length];
	DecryptString(EncryptedPsSetCreateThreadNotifyRoutineString, PsSetCreateThreadNotifyRoutineBuffer);
	const ULONG_PTR RoutineAddress = reinterpret_cast<ULONG_PTR>(GetProcedureAddress(NtoskrnlBase, PsSetCreateThreadNotifyRoutineBuffer));
	if (RoutineAddress == 0)
	{
		Printf("Failed to obtain address for %hs\n", PsSetCreateThreadNotifyRoutineBuffer);
		return STATUS_PROCEDURE_NOT_FOUND;
	}
	RtlSecureZeroMemory(PsSetCreateThreadNotifyRoutineBuffer, decltype(EncryptedPsSetCreateThreadNotifyRoutineString)::Length);

	// Start at PsSetThreadNR and search for the byte pattern to obtain the offset to PspNotifyEnableMask
	// Assume PsSetThreadNR to be no bigger than 512 bytes, or PsSetThreadNR to be no further than this
	// from PspSetCreateThreadNotifyRoutine. // TODO: in the second case, properly resolve call target and start search there
	constexpr const SIZE_T MAX_SEARCH_SIZE = 0x200;
	constexpr const UCHAR PspNotifyEnableMaskSearchPattern[] =
	{
		0xA8, 0x08,									// test al, 8
		0x75, 0x09,									// jnz +9
		0xF0, 0x0F, 0xBA, 0x2D, // [XX XX XX XX 03]	// lock bts cs:PspNotifyEnableMask, 3
	};

	// Start at PsSetThreadNR - 0x200 (in case compiler placed PspSetCreateThreadNotifyRoutine before PsSetThreadNR) and search up to PsSetThreadNR + 0x200
	for (PUCHAR Address = reinterpret_cast<PUCHAR>(max(RoutineAddress - MAX_SEARCH_SIZE, NtoskrnlBase + PAGE_SIZE));
		reinterpret_cast<ULONG_PTR>(Address) < RoutineAddress + MAX_SEARCH_SIZE;
		++Address)
	{
		if (memcmp(Address, PspNotifyEnableMaskSearchPattern, sizeof(PspNotifyEnableMaskSearchPattern)) == 0)
		{
			const LONG RelativeOffset = *reinterpret_cast<PLONG>(Address + sizeof(PspNotifyEnableMaskSearchPattern));
			Data->pPspNotifyEnableMask = reinterpret_cast<PULONG>(Address + sizeof(PspNotifyEnableMaskSearchPattern) + 5 + RelativeOffset);
			break;
		}
	}

	if (Data->pPspNotifyEnableMask == nullptr)
		Printf("Failed to find address of PspNotifyEnableMask\n");
	else
		Printf("Found PspNotifyEnableMask at 0x%p\n", Data->pPspNotifyEnableMask);

	return Data->pPspNotifyEnableMask != nullptr
		? STATUS_SUCCESS
		: STATUS_NOT_FOUND;
}

NTSTATUS
LocateMmUnloadedDrivers(
	_Inout_ PDYNAMIC_DATA Data
	)
{
	PAGED_CODE();

	Data->MmUnloadedDrivers = nullptr;
	Data->MmLastUnloadedDriver = nullptr;

	if (NtoskrnlBase == 0 || NtoskrnlSize == 0)
		return STATUS_INVALID_IMAGE_FORMAT;

	// Find 'mov rXX, MmUnloadedDrivers' in MmLocateUnloadedDriver
	const UCHAR MovMmUnloadedDriversPattern[] = { 0x4C, 0x8B, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0x4C, 0x8B, 0xC9, 0x4D, 0x85, 0xCC, 0x74 };
	const ULONG_PTR MovMmUnloadedDrivers = FindPattern(NtoskrnlBase, NtoskrnlSize, MovMmUnloadedDriversPattern, sizeof(MovMmUnloadedDriversPattern));
	if (MovMmUnloadedDrivers != 0)
	{
		Data->MmUnloadedDrivers = reinterpret_cast<PUNLOADED_DRIVER*>(reinterpret_cast<PUCHAR>(MovMmUnloadedDrivers) +
			*reinterpret_cast<PLONG>(reinterpret_cast<PUCHAR>(MovMmUnloadedDrivers) + 3) + 7); // 3 mov bytes before offset, instruction length 7

		// Now find a 'mov [ecx|edx], MmLastUnloadedDriver' - should be within ~20 bytes
		const UCHAR MovMmLastUnloadedDriverPattern[] = { 0x8B, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xFF };
		const ULONG_PTR MovMmLastUnloadedDriver = FindPattern(MovMmUnloadedDrivers, 32, MovMmLastUnloadedDriverPattern, sizeof(MovMmLastUnloadedDriverPattern));
		if (MovMmLastUnloadedDriver != 0)
		{
			Data->MmLastUnloadedDriver = reinterpret_cast<PULONG>(reinterpret_cast<PUCHAR>(MovMmLastUnloadedDriver) +
				*reinterpret_cast<PLONG>(reinterpret_cast<PUCHAR>(MovMmLastUnloadedDriver) + 2) + 6); // 2 mov bytes before offset, instruction length 6
		}
	}

	if (Data->MmUnloadedDrivers == nullptr)
		Printf("Failed to find address of MmUnloadedDrivers\n");
	else
	{
		Printf("Found MmUnloadedDrivers at 0x%p\n", Data->MmUnloadedDrivers);

		if (Data->MmLastUnloadedDriver == nullptr)
			Printf("Failed to find address of MmLastUnloadedDriver\n");
		else
		{
			Printf("Found MmLastUnloadedDriver at 0x%p\n", Data->MmLastUnloadedDriver);
			if (*Data->MmLastUnloadedDriver > 50) // Sanity check
			{
				Printf("Bogus value for MmLastUnloadedDriver: expected <= 50, actual value = %u\n", *Data->MmLastUnloadedDriver);
				return STATUS_DATA_NOT_ACCEPTED;
			}
		}
	}

	return Data->MmUnloadedDrivers != nullptr && Data->MmLastUnloadedDriver != nullptr
		? STATUS_SUCCESS
		: STATUS_NOT_FOUND;
}

NTSTATUS
LocatePiDDBCacheTable(
	_Inout_ PDYNAMIC_DATA Data
	)
{
	PAGED_CODE();

	Data->PiDDBLock = nullptr;
	Data->PiDDBCacheTable = nullptr;

	if (NtoskrnlBase == 0 || NtoskrnlSize == 0)
		return STATUS_INVALID_IMAGE_FORMAT;

	PIMAGE_NT_HEADERS NtHeaders = RtlpImageNtHeaderEx(reinterpret_cast<PVOID>(NtoskrnlBase), NtoskrnlSize);
	if (NtHeaders == nullptr)
		return STATUS_INVALID_IMAGE_FORMAT;

	// Find the PAGE section
	PIMAGE_SECTION_HEADER PageSection = nullptr;
	PIMAGE_SECTION_HEADER Section = IMAGE_FIRST_SECTION(NtHeaders);
	for (USHORT i = 0; i < NtHeaders->FileHeader.NumberOfSections; ++i)
	{
		CHAR SectionName[IMAGE_SIZEOF_SHORT_NAME + 1];
		RtlCopyMemory(SectionName, Section->Name, IMAGE_SIZEOF_SHORT_NAME);
		SectionName[IMAGE_SIZEOF_SHORT_NAME] = '\0';
		if (strcmp(SectionName, "PAGE") == 0)
		{
			PageSection = Section;
			break;
		}
		Section++;
	}

	NT_ASSERT(PageSection != nullptr);

	// Find 'mov ebx, 0C0000001h, call RtlIsGenericTableEmptyAvl, test al, al' in PiLookupInDDBCache in PAGE section
	const UCHAR PiLookupInDDBCachePattern[] = { 0xBB, 0x01, 0x00, 0x00, 0xC0, 0xE8, 0xCC, 0xCC, 0xCC, 0xCC, 0x84, 0xC0 };
	const ULONG_PTR PiLookupInDDBCacheAddress = FindPattern(NtoskrnlBase + PageSection->VirtualAddress,
		NtoskrnlSize - PageSection->VirtualAddress, PiLookupInDDBCachePattern, sizeof(PiLookupInDDBCachePattern));
	if (PiLookupInDDBCacheAddress != 0)
	{
		// Find function start
		const ULONG_PTR PiLookupInDDBCache = BacktrackToFunctionStart(reinterpret_cast<PUCHAR>(PiLookupInDDBCacheAddress),
			reinterpret_cast<PUCHAR>(PiLookupInDDBCacheAddress) - 512);
		if (PiLookupInDDBCache != 0)
		{
			// Find 'lea rcx, PiDDBCacheTable' in PiLookupInDDBCache
			const UCHAR LeaRcxPiDDBCacheTablePattern[] = { 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xCC };
			const ULONG_PTR LeaRcxPiDDBCacheTable = FindPattern(PiLookupInDDBCache, 128, LeaRcxPiDDBCacheTablePattern, sizeof(LeaRcxPiDDBCacheTablePattern));
			if (LeaRcxPiDDBCacheTable != 0)
			{
				Data->PiDDBCacheTable = reinterpret_cast<PRTL_AVL_TABLE>(reinterpret_cast<PUCHAR>(LeaRcxPiDDBCacheTable) +
					*reinterpret_cast<PLONG>(reinterpret_cast<PUCHAR>(LeaRcxPiDDBCacheTable) + 3) + 7); // 3 lea bytes before offset, instruction length 7
			}
		}
	}

	// Find 'mov ebx, eax, cmp eax, 0C0000001h, jnz XX, mov r9, [rsp+XX], lea rcx, XX' in PpCheckInDriverDatabase in PAGE section
	const UCHAR PpCheckInDriverDatabasePattern[] = { 0x8B, 0xD8, 0x3D, 0x01, 0x00, 0x00, 0xC0, 0x75, 0xCC, 0x4C, 0x8B, 0x8C, 0x24, 0xCC, 0x00, 0x00, 0x00, 0x48, 0x8D };
	const ULONG_PTR PpCheckInDriverDatabaseAddress = FindPattern(NtoskrnlBase + PageSection->VirtualAddress,
		NtoskrnlSize - PageSection->VirtualAddress, PpCheckInDriverDatabasePattern, sizeof(PpCheckInDriverDatabasePattern));
	if (Data->PiDDBCacheTable != nullptr && PpCheckInDriverDatabaseAddress != 0)
	{
		// Find function start
		const ULONG_PTR PpCheckInDriverDatabase = BacktrackToFunctionStart(reinterpret_cast<PUCHAR>(PpCheckInDriverDatabaseAddress),
			reinterpret_cast<PUCHAR>(PpCheckInDriverDatabaseAddress) - 512);
		if (PpCheckInDriverDatabase != 0)
		{
			// Find 'lea rcx, PiDDBLock' in PpCheckInDriverDatabase
			const UCHAR LeaRcxPiDDBLockPattern[] = { 0x48, 0x8D, 0x0D, 0xCC, 0xCC, 0xCC, 0xFF }; // PiDDBLock is in .data so the offset will always be negative
			const ULONG_PTR LeaRcxPiDDBLock = FindPattern(PpCheckInDriverDatabase, 128, LeaRcxPiDDBLockPattern, sizeof(LeaRcxPiDDBLockPattern));
			if (LeaRcxPiDDBLock != 0)
			{
				Data->PiDDBLock = reinterpret_cast<PERESOURCE>(reinterpret_cast<PUCHAR>(LeaRcxPiDDBLock) +
					*reinterpret_cast<PLONG>(reinterpret_cast<PUCHAR>(LeaRcxPiDDBLock) + 3) + 7); // 3 lea bytes before offset, instruction length 7
			}
		}
	}

	if (Data->PiDDBCacheTable == nullptr)
		Printf("Failed to find address of PiDDBCacheTable\n");
	else
	{
		Printf("Found PiDDBCacheTable at 0x%p\n", Data->PiDDBCacheTable);
		if (Data->PiDDBLock == nullptr)
			Printf("WARNING: PiDDBLock was not found. PiDDBCacheTable will not be locked during entry removal!\n");
		else
			Printf("Found PiDDBLock at 0x%p\n", Data->PiDDBLock);
	}

	return Data->PiDDBCacheTable != nullptr
		? STATUS_SUCCESS
		: STATUS_NOT_FOUND;
}

// Tandasat's RS4 page table search method for possible future reference. Not currently called
#if 0
static
PVOID
MemMem(
	_In_ const void* SearchBase,
	_In_ SIZE_T SearchSize,
	_In_ const void* Pattern,
	_In_ SIZE_T PatternSize)
{
	if (PatternSize > SearchSize)
	{
		return nullptr;
	}

	auto Base = static_cast<PCCH>(SearchBase);
	for (SIZE_T i = 0; i <= SearchSize - PatternSize; i++)
	{
		if (RtlCompareMemory(Pattern, &Base[i], PatternSize) == PatternSize)
		{
			return const_cast<PCHAR>(&Base[i]);
		}
	}
	return nullptr;
}

static
VOID
LocatePageTablesForRS4(
	_Inout_ PDYNAMIC_DATA Data,
	_In_ CONST PUCHAR MiGetPhysicalAddress
	)
{
	// Search the below pattern up to 0x20 bytes from the beginning of
	// MiGetPhysicalAddress to detect the call instruction to MI_IS_PHYSICAL_ADDRESS.
	static const UCHAR CallMI_IS_PHYSICAL_ADDRESSPattern[] =
	{
		0x49, 0x8B, 0xF8,	// mov	rdi, r8
		0x48, 0x8B, 0xF2,	// mov	rsi, rdx
		0x48, 0x8B, 0xD9,	// mov	rbx, rcx
		0xE8,				// call	MI_IS_PHYSICAL_ADDRESS
	};
	auto FoundAddress = reinterpret_cast<PCUCHAR>(MemMem(
		MiGetPhysicalAddress, 0x20, CallMI_IS_PHYSICAL_ADDRESSPattern, sizeof(CallMI_IS_PHYSICAL_ADDRESSPattern)));
	if (FoundAddress == nullptr)
	{
		return;
	}

	// Add 9 to shift to 0xE8 (an address of the call instruction), then get an
	// offset, compute an address of MI_IS_PHYSICAL_ADDRESS.
	PCUCHAR offsetToCallInstruction = FoundAddress + 9;
	LONG offsetToMI_IS_PHYSICAL_ADDRESS = *reinterpret_cast<CONST LONG*>(offsetToCallInstruction + 1);
	PCUCHAR AddressOfMI_IS_PHYSICAL_ADDRESS = offsetToCallInstruction + 5 + offsetToMI_IS_PHYSICAL_ADDRESS;

	// Search an embeded PTE base from the beginning of MI_IS_PHYSICAL_ADDRESS
	// up to 0x20 bytes.
	static const UCHAR PteBasePattern[] =
	{
		0x49, 0xB8, 0xF8, 0xFF, 0xFF, 0xFF, 0x7F, 0x00, 0x00, 0x00,	// mov	r8, 7FFFFFFFF8h
		0x49, 0x23, 0xC8,											// and	rcx, r8
		0x48, 0xBA,													// mov	rdx, 0FFFFF68000000000h
	};
	FoundAddress = reinterpret_cast<PCUCHAR>(MemMem(
		AddressOfMI_IS_PHYSICAL_ADDRESS, 0x20, PteBasePattern, sizeof(PteBasePattern)));
	if (FoundAddress == nullptr)
	{
		return;
	}

	// Add 15 to shift t0 the address where the PTE base is written (after 0x48, 0xBA).
	// Then compute the PDE base from the PTE base, set them to 'Data'.
	ULONG_PTR PteBase = *reinterpret_cast<CONST ULONG_PTR*>(FoundAddress + 15);
	ULONG_PTR Index = (PteBase >> PXI_SHIFT) & PXI_MASK;
	ULONG_PTR PdeBase = PteBase | (Index << PPI_SHIFT);

	Data->DYN_PDE_BASE = PdeBase;
	Data->DYN_PTE_BASE = PteBase;
}
#endif
