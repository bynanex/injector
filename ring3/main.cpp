#include "ntdll.h"
#include "util.h"
#include <ntstatus.h>
#include <strings.h>

typedef ANSI_STRING StringType; // Set to either ANSI_STRING or UNICODE_STRING; don't mix different string types in one run.
static constexpr const ULONG64 StartNonce = 0x58cb67fa57e51c39; // Set this to (last used nonce + 1) prior to running this
static constexpr const StringType InputStrings[] = // Input strings to encrypt. First string will have nonce == StartNonce, the next will have StartNonce + 1... etc.
{
	RTL_CONSTANT_ANSI_STRING("EtwpCreateEtwThread"),
	RTL_CONSTANT_ANSI_STRING("RtlActivateActivationContextEx"),
	RTL_CONSTANT_ANSI_STRING("RtlCreateActivationContext"),
	RTL_CONSTANT_ANSI_STRING("RtlQueryActivationContextApplicationSettings"),
	RTL_CONSTANT_ANSI_STRING("RtlValidateHeap"),
	RTL_CONSTANT_ANSI_STRING("TpStartAsyncIoOperation"),
	RTL_CONSTANT_ANSI_STRING("TpWaitForWork"),
	RTL_CONSTANT_ANSI_STRING("WinSqmEventWrite")
};

int wmain()
{
	NTSTATUS Status = STATUS_SUCCESS;
	ULONG64 Nonce = StartNonce;

	for (ULONG i = 0; i < ARRAYSIZE(InputStrings); ++i)
	{
		const ULONG Length = static_cast<ULONG>(InputStrings[i].MaximumLength); // sizeof() for both CHAR and WCHAR, i.e. size in bytes incl. null terminator
		const PUCHAR PlainTextBuffer = reinterpret_cast<PUCHAR>(InputStrings[i].Buffer);
		const PUCHAR Encrypted = static_cast<PUCHAR>(RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, Length));
		RtlCopyMemory(Encrypted, PlainTextBuffer, Length);

		if (s20_crypt(const_cast<PUCHAR>(EncryptionKey),
					S20_KEYLEN_128,
					PUCHAR(&Nonce),
					0,
					Encrypted,
					Length) != S20_SUCCESS)
		{
			Printf(L"Encryption failure\n");
			__debugbreak();
			Status = STATUS_UNSUCCESSFUL;
			break;
		}

		// Print C++ declaration for easy copy/pasting
		if constexpr (sizeof(StringType::Buffer[0]) == sizeof(WCHAR))
			// ReSharper disable once CppUnreachableCode // What the fuck do you think constexpr stands for Resharper
			Printf(L"CONSTEXPR CONST ENCRYPTED_STRING<sizeof(L\"%ls\")> Encrypted%lsString =\n",
				reinterpret_cast<PWCHAR>(PlainTextBuffer), reinterpret_cast<PWCHAR>(PlainTextBuffer));
		else
			// ReSharper disable once CppUnreachableCode
			Printf(L"CONSTEXPR CONST ENCRYPTED_STRING<sizeof(\"%hs\")> Encrypted%hsString =\n",
				reinterpret_cast<PCHAR>(PlainTextBuffer), reinterpret_cast<PCHAR>(PlainTextBuffer));
		Printf(L"{\n\t0x%p,\n\t{ ", reinterpret_cast<PVOID>(Nonce));
		for (ULONG j = 0; j < Length; ++j)
			Printf(L"0x%02X%ls", Encrypted[j], j < Length - 1 ? L", " : L" ");
		Printf(L"}\n};\n\n");

		// Free buffer and increment nonce by 1 for next string
		RtlFreeHeap(RtlProcessHeap(), 0, Encrypted);
		Nonce++;
	}

	Printf(L"\nPress any key to exit.\n");
	WaitForKey();
	return NtTerminateProcess(NtCurrentProcess, Status);
}
