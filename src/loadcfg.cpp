// Debug builds are built with /GS bloat enabled, so they don't need this file
#if !defined(_DEBUG) && (!defined(DBG) || !DBG)

#include "injector.h"
#include <ntimage.h>

// Generate a BS load config directory to satisfy checked kernels >= 8.1, or all loaders (ntdll or ntoskrnl, both CHK and FRE) if image subsystem version >= 6.03
extern "C"
{
#ifdef _M_IX86
	extern ULONG __safe_se_handler_table;
	extern ULONG __safe_se_handler_count;

	uintptr_t __security_cookie = 0xBB40E64E; // This is a Fucking Serious magic value. Ntdll won't load a PE if you change it, and ntoskrnl will simply bugcheck

	#ifdef _KERNEL_MODE
		void __fastcall __security_check_cookie(uintptr_t) {}
		__declspec(noreturn) void __cdecl __report_rangecheckfailure() {}
	#endif
#else
	uintptr_t __security_cookie = 0x2B992DDFA232; // Likewise on x64
#endif

	extern "C" const IMAGE_LOAD_CONFIG_DIRECTORY _load_config_used =
	{
		// Choices, choices...
		// (1) Minimum size to be allowed to load (as of Win 10 RS3 - the fascists may change this again in the future of course):
		//FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY, SEHandlerCount) + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY::SEHandlerCount),

		// Pretty good, but there's also...
		// (2) Minimum size needed to tell the loader to fuck off with its useless fucking stack cookie. (This value is used here.)
		FIELD_OFFSET(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags) + sizeof(IMAGE_LOAD_CONFIG_DIRECTORY::GuardFlags),
		0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // Fields TimeDateStamp through EditList
		reinterpret_cast<decltype(IMAGE_LOAD_CONFIG_DIRECTORY::SecurityCookie)>(&__security_cookie), // "Security"Cookie. Hopefully not ever actually used
#ifdef _M_IX86
		reinterpret_cast<ULONG>(&__safe_se_handler_table),	// SEHandlerTable
		reinterpret_cast<ULONG>(&__safe_se_handler_count),	// SEHandlerCount
#else
		0,		// SEHandlerTable - N/A on x64
		0,		// SEHandlerCount - N/A on x64
#endif
		0,		// GuardCFCheckFunctionPointer. CFG only, but dummy function pointers are "helpfully" inserted for you by the CRT even with it off
		0,		// GuardCFDispatchFunctionPointer. Same
		0,		// GuardCFFunctionTable
		0,		// GuardCFFunctionCount
		IMAGE_GUARD_SECURITY_COOKIE_UNUSED // GuardFlags // HA HA HA SUCK MY DICK
		/* Remaining Windows 10 shit omitted */
	};
}

#endif
