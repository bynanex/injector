#include "injector.h"
#include "util.h"
#include "strings.h"
#include <bcrypt.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(PAGE, DecryptPeFile)
#endif

#define BLOCK_SIZE		128
#define KEY_SIZE		128

// Symmetric key private bytes
static const UCHAR SecretKey[] =
{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F
};

NTSTATUS
DecryptPeFile(
	_In_ PUCHAR EncryptedDllBuffer,
	_In_ SIZE_T EncryptedDllSize,
	_Out_ PUCHAR *DecryptedDllBuffer,
	_Out_ PSIZE_T DecryptedDllSize,
	_Out_ PIMAGE_NT_HEADERS *NtHeaders
	)
{
	PAGED_CODE();

	*DecryptedDllBuffer = nullptr;
	*DecryptedDllSize = 0;
	*NtHeaders = nullptr;

	// Try the obvious first, in case the file is not encrypted
	const PIMAGE_NT_HEADERS Headers = RtlpImageNtHeaderEx(EncryptedDllBuffer, EncryptedDllSize);
	if (Headers != nullptr)
	{
		// Not encrypted - copy buffer and return
		*DecryptedDllBuffer = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPoolNx, EncryptedDllSize, GetPoolTag()));
		if (*DecryptedDllBuffer == nullptr)
			return STATUS_NO_MEMORY;

		RtlCopyMemory(*DecryptedDllBuffer, EncryptedDllBuffer, EncryptedDllSize);
		*DecryptedDllSize = EncryptedDllSize;
		*NtHeaders = Headers;

		return STATUS_SUCCESS;
	}

	// File is encrypted (or garbage...). Set up parameters
	const ULONG BlockLength = BLOCK_SIZE / CHAR_BIT;
	BCRYPT_ALG_HANDLE AlgorithmHandle = nullptr;
	BCRYPT_KEY_HANDLE KeyHandle = nullptr;
	PUCHAR KeyObject = nullptr, PaddedPlaintextBuffer = nullptr;
	ULONG KeyObjectLength = 0, PaddedPlaintextLength = 0;
	UCHAR Iv[BLOCK_SIZE / CHAR_BIT]; // Bogus IV; contents can be anything since the first CBC block will be skipped

	// Decrypt strings
	WCHAR AESName[decltype(EncryptedAESString)::Length];
	WCHAR BlockLengthName[decltype(EncryptedBlockLengthString)::Length];
	WCHAR ChainingModeName[decltype(EncryptedChainingModeString)::Length];
	WCHAR ChainingModeCBCName[decltype(EncryptedChainingModeCBCString)::Length];
	WCHAR ObjectLengthName[decltype(EncryptedObjectLengthString)::Length];
	DecryptString(EncryptedAESString, AESName);
	DecryptString(EncryptedBlockLengthString, BlockLengthName);
	DecryptString(EncryptedChainingModeString, ChainingModeName);
	DecryptString(EncryptedChainingModeCBCString, ChainingModeCBCName);
	DecryptString(EncryptedObjectLengthString, ObjectLengthName);

	// Open an AES algorithm handle
	NTSTATUS Status = BCryptOpenAlgorithmProvider(&AlgorithmHandle,
												AESName, // BCRYPT_AES_ALGORITHM
												nullptr,
												BCRYPT_PROV_DISPATCH); // Load provider as nonpaged (even if we are at PASSIVE)
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptOpenAlgorithmProvider: error 0x%08X\n", Status);
		goto Exit;
	}

	// Get the block size and verify it matches our hardcoded one
	ULONG BlockLengthCheck, ResultSize;
	Status = BCryptGetProperty(AlgorithmHandle,
								BlockLengthName, // BCRYPT_BLOCK_LENGTH
								reinterpret_cast<PUCHAR>(&BlockLengthCheck),
								sizeof(BlockLengthCheck),
								&ResultSize,
								0);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptGetProperty(BCRYPT_BLOCK_LENGTH): error 0x%08X\n", Status);
		goto Exit;
	}
	if (BlockLengthCheck != BlockLength)
	{
		Printf("BCryptGetProperty(BCRYPT_BLOCK_LENGTH) returned %u bytes; expected %u.\n", BlockLengthCheck, BlockLength);
		goto Exit;
	}

	// Set the block chaining mode to CBC
	Status = BCryptSetProperty(AlgorithmHandle,
								ChainingModeName, // BCRYPT_CHAINING_MODE
								reinterpret_cast<PUCHAR>(ChainingModeCBCName), // BCRYPT_CHAIN_MODE_CBC
								sizeof(BCRYPT_CHAIN_MODE_CBC),
								0);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptSetProperty(BCRYPT_CHAINING_MODE): error 0x%08X\n", Status);
		goto Exit;
	}

	// Calculate the size of the buffer needed to hold the key object
	Status = BCryptGetProperty(AlgorithmHandle,
								ObjectLengthName, // BCRYPT_OBJECT_LENGTH
								reinterpret_cast<PUCHAR>(&KeyObjectLength),
								sizeof(KeyObjectLength),
								&ResultSize,
								0);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptGetProperty(BCRYPT_OBJECT_LENGTH): error 0x%08X\n", Status);
		goto Exit;
	}

	// Allocate a buffer for the key object
	KeyObject = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPoolNx, KeyObjectLength, GetPoolTag()));
	RtlZeroMemory(KeyObject, KeyObjectLength);

	// Generate the key object from the input key bytes
	Status = BCryptGenerateSymmetricKey(AlgorithmHandle,
										&KeyHandle,
										KeyObject,
										KeyObjectLength,
										const_cast<PUCHAR>(SecretKey),
										sizeof(SecretKey),
										0);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptGenerateSymmetricKey: error 0x%08X\n", Status);
		goto Exit;
	}

	// Get the output buffer size (including the prepended block)
	Status = BCryptDecrypt(KeyHandle,
							EncryptedDllBuffer,
							static_cast<ULONG>(EncryptedDllSize),
							nullptr,
							Iv,
							BlockLength,
							nullptr,
							0,
							&PaddedPlaintextLength,
							BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptDecrypt (1): error 0x%08X\n", Status);
		goto Exit;
	}

	// Allocate two buffers: one (which will be freed) with room for the prepended garbage block, and one buffer for the 'clean' output
	const ULONG PlaintextLength = PaddedPlaintextLength - BlockLength;
	PaddedPlaintextBuffer = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPoolNx, PaddedPlaintextLength, GetPoolTag()));
	const PUCHAR PlaintextBuffer = static_cast<PUCHAR>(ExAllocatePoolWithTag(NonPagedPoolNx, PlaintextLength, GetPoolTag()));
	if (PaddedPlaintextBuffer == nullptr || PlaintextBuffer == nullptr)
	{
		Status = STATUS_NO_MEMORY;
		goto Exit;
	}
	RtlZeroMemory(PaddedPlaintextBuffer, PaddedPlaintextLength);
	RtlZeroMemory(PlaintextBuffer, PlaintextLength);

	// Decrypt the buffer
	Status = BCryptDecrypt(KeyHandle,
							EncryptedDllBuffer,
							static_cast<ULONG>(EncryptedDllSize),
							nullptr,
							Iv,
							BlockLength,
							PaddedPlaintextBuffer,
							PlaintextLength + BlockLength,
							&PaddedPlaintextLength,
							BCRYPT_BLOCK_PADDING);
	if (!NT_SUCCESS(Status))
	{
		Printf("BCryptDecrypt (2): error 0x%08X\n", Status);
		goto Exit;
	}

	// Copy the decrypted buffer to the output buffer and skip the first block
	RtlCopyMemory(PlaintextBuffer, PaddedPlaintextBuffer + BlockLength, PlaintextLength);

	// Set the return parameters now, so that the buffer will be freed even if the image is invalid
	*DecryptedDllBuffer = PlaintextBuffer;
	*DecryptedDllSize = PlaintextLength;
	*NtHeaders = RtlpImageNtHeaderEx(PlaintextBuffer, PlaintextLength);

	if (*NtHeaders == nullptr)
	{
		Printf("Decrypted buffer is not a valid PE file!\n");
		Status = STATUS_INVALID_IMAGE_NOT_MZ;
		goto Exit;
	}

	Status = STATUS_SUCCESS;

Exit:
	RtlSecureZeroMemory(AESName, decltype(EncryptedAESString)::Length);
	RtlSecureZeroMemory(BlockLengthName, decltype(EncryptedBlockLengthString)::Length);
	RtlSecureZeroMemory(ChainingModeName, decltype(EncryptedChainingModeString)::Length);
	RtlSecureZeroMemory(ChainingModeCBCName, decltype(EncryptedChainingModeCBCString)::Length);
	RtlSecureZeroMemory(ObjectLengthName, decltype(EncryptedObjectLengthString)::Length);

	if (AlgorithmHandle != nullptr)
	{
		BCryptCloseAlgorithmProvider(AlgorithmHandle, 0);
	}

	if (KeyHandle != nullptr)
	{
		BCryptDestroyKey(KeyHandle);
	}

	if (KeyObject != nullptr)
	{
		RtlSecureZeroMemory(KeyObject, KeyObjectLength);
		ExFreePool(KeyObject);
	}

	if (PaddedPlaintextBuffer != nullptr)
	{
		RtlSecureZeroMemory(PaddedPlaintextBuffer, PaddedPlaintextLength);
		ExFreePool(PaddedPlaintextBuffer);
	}

	return Status;
}
