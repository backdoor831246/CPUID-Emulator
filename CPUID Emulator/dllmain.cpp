#include "pch.h"
#include <windows.h>
#include <set>

static std::set<ULONG64> g_CpuidAddresses;
static BYTE g_UdHook[2] = { 0x0F, 0x0B };

static LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS pEx) {
	if (pEx->ExceptionRecord->ExceptionCode != STATUS_ILLEGAL_INSTRUCTION)
		return EXCEPTION_CONTINUE_SEARCH;

	ULONG64 addr = (ULONG64)pEx->ExceptionRecord->ExceptionAddress;
	if (g_CpuidAddresses.find(addr) == g_CpuidAddresses.end())
		return EXCEPTION_CONTINUE_SEARCH;

	PCONTEXT ctx = pEx->ContextRecord;
	DWORD leaf = (DWORD)ctx->Rax;

	ctx->Rax = 0; ctx->Rbx = 0; ctx->Rcx = 0; ctx->Rdx = 0;

	switch (leaf) {
	case 0:
		ctx->Rax = 0x16;
		//ctx->Rbx = 0x756E6547; // "Genu"
		//ctx->Rdx = 0x49656E69; // "ineI"
		//ctx->Rcx = 0x6C65746E; // "ntel"

		//ctx->Rbx = 0x68747541; // "Auth"
		//ctx->Rdx = 0x69746E65; // "enti"
		//ctx->Rcx = 0x444D4163; // "cAMD"

		ctx->Rbx = 0x7263694D; // "Micr"
		ctx->Rdx = 0x666F736F; // "osof"
		ctx->Rcx = 0x76482074; // "t Hv"
		break;
	case 1:
		ctx->Rax = 0x000906ED;
		ctx->Rbx = 0x02100800;
		ctx->Rcx = 0x7FFAFBBF;
		ctx->Rdx = 0xBFEBFBFF;
		break;
	case 7:
		ctx->Rbx = 0x029C67AF;
		break;
	case 0x80000000:
		ctx->Rax = 0x80000008;
		break;
	case 0x80000001:
		ctx->Rcx = 0x00000121;
		ctx->Rdx = 0x2C100800;
		break;
	case 0x80000002:
	case 0x80000003:
	case 0x80000004: {
		char brand[49] = "Intel(R) Core(TM) i9-13900K CPU @ 3.00GHz     ";
		// char brand[49] = "Intel(R) Core(TM) i9-14900K CPU @ 3.20GHz     ";
		// char brand[49] = "Intel(R) Core(TM) i9-13900KS CPU @ 3.20GHz     ";
		// char brand[49] = "Intel(R) Core(TM) i7-13700K CPU @ 3.40GHz      ";
		// char brand[49] = "Intel(R) Core(TM) i5-13600K CPU @ 3.50GHz      ";
		// char brand[49] = "Intel(R) Core(TM) i9-12900KS CPU @ 3.40GHz     ";
		// char brand[49] = "Intel(R) Core(TM) i7-12700KF CPU @ 3.60GHz     ";
		// char brand[49] = "Intel(R) Core(TM) i7-11700K CPU @ 3.60GHz      ";
		// char brand[49] = "Intel(R) Core(TM) i5-10600K CPU @ 4.10GHz      ";
		// char brand[49] = "Intel(R) Xeon(R) CPU E5-2689 v4 @ 3.10GHz      ";
		// char brand[49] = "Intel(R) Xeon(R) Platinum 8370C CPU @ 2.80GHz  ";
		// char brand[49] = "AMD Ryzen 9 7950X 16-Core Processor            ";
		// char brand[49] = "AMD Ryzen 9 7900X 12-Core Processor            ";
		// char brand[49] = "AMD Ryzen 7 7800X3D 8-Core Processor           ";
		// char brand[49] = "AMD Ryzen 7 7700X 8-Core Processor             ";
		// char brand[49] = "AMD Ryzen 5 7600X 6-Core Processor             ";
		// char brand[49] = "AMD Ryzen 9 5950X 16-Core Processor            ";
		// char brand[49] = "AMD Ryzen 7 5800X 8-Core Processor             ";
		// char brand[49] = "AMD Ryzen 5 5600X 6-Core Processor             ";
		// char brand[49] = "AMD Ryzen Threadripper 3990X 64-Core Processor ";
		DWORD offset = (leaf - 0x80000002) * 16;
		memcpy(&ctx->Rax, brand + offset + 0, 4);
		memcpy(&ctx->Rbx, brand + offset + 4, 4);
		memcpy(&ctx->Rcx, brand + offset + 8, 4);
		memcpy(&ctx->Rdx, brand + offset + 12, 4);
		break;
	}
	case 0x80000008:
		ctx->Rax = 0x00003027;
		break;
	}

	ctx->Rip += 2;
	return EXCEPTION_CONTINUE_EXECUTION;
}

static void ScanAndHook(PVOID base, SIZE_T size) {
	BYTE *p = (BYTE*)base;
	for (SIZE_T i = 0; i < size - 1; i++) {
		if (p[i] == 0x0F && p[i + 1] == 0xA2) {
			ULONG64 addr = (ULONG64)base + i;
			g_CpuidAddresses.insert(addr);
			DWORD old;
			VirtualProtect((LPVOID)addr, 2, PAGE_EXECUTE_READWRITE, &old);
			memcpy((LPVOID)addr, g_UdHook, 2);
			VirtualProtect((LPVOID)addr, 2, old, &old);
			FlushInstructionCache(GetCurrentProcess(), (LPVOID)addr, 2);
		}
	}
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(hModule);
		AddVectoredExceptionHandler(1, VectoredHandler);

		HMODULE hMain = GetModuleHandleA(NULL);
		PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMain;
		PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMain + dos->e_lfanew);
		SIZE_T text_size = nt->OptionalHeader.SizeOfCode;
		BYTE  *text_base = (BYTE*)hMain + nt->OptionalHeader.BaseOfCode;

		ScanAndHook(text_base, text_size);

		char msg[64];
		wsprintfA(msg, "Patches applied: %d", (int)g_CpuidAddresses.size());
		MessageBoxA(NULL, msg, "CPUID Spoof", MB_OK);
	}
	return TRUE;
}