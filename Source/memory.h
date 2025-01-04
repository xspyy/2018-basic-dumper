// RESTORED BY XSPY
#pragma once
#include <DbgHelp.h>

namespace Memory {
	bool Compare(const BYTE* pData, const BYTE* bMask, const char* szMask)
	{
		for (; *szMask; ++szMask, ++pData, ++bMask)
			if (*szMask == 'x' && *pData != *bMask) return 0;
		return (*szMask) == NULL;
	}

	DWORD FindPattern(DWORD dwAddress, DWORD dwLen, BYTE* bMask, char* szMask) {
		for (DWORD i = 0; i < dwLen; i++)
			if (Compare((BYTE*)(dwAddress + i), bMask, szMask))  return (DWORD)(dwAddress + i);
		return 0;
	}

	int Scan(DWORD mode, char* content, char* mask) {
		DWORD PageSize;
		SYSTEM_INFO si;
		GetSystemInfo(&si);
		PageSize = si.dwPageSize;
		MEMORY_BASIC_INFORMATION mi;
		for (DWORD lpAddr = 0; lpAddr < 0x7FFFFFFF; lpAddr += PageSize)
		{
			DWORD vq = VirtualQuery((void*)lpAddr, &mi, PageSize);
			if (vq == ERROR_INVALID_PARAMETER || vq == 0) break;
			if (mi.Type == MEM_MAPPED) continue;
			if (mi.Protect == mode)
			{
				int addr = FindPattern(lpAddr, PageSize, (PBYTE)content, mask);
				if (addr != 0)
				{
					return addr;
				}
			}
		}
	}

	DWORD getSegmentAddr(const char* s) {
		DWORD dllImageBase = 0x400000;
		HMODULE hModule = GetModuleHandleA(0);
		IMAGE_NT_HEADERS* pNtHdr = ImageNtHeader(hModule);

		IMAGE_SECTION_HEADER* pSectionHdr = (IMAGE_SECTION_HEADER*)(pNtHdr + 1);
		for (int i = 0; i < pNtHdr->FileHeader.NumberOfSections; i++)
		{
			char* name = (char*)pSectionHdr->Name;
			if (memcmp(name, s, strlen(s)) == 0)
			{
				DWORD addr = dllImageBase + pSectionHdr->VirtualAddress;
				return addr;
				break;
			}
			pSectionHdr++;
		}
	}

	const char* getSegmentName(DWORD adr) {
		HMODULE hModule = (HMODULE)adr;
		IMAGE_NT_HEADERS* pNtHdr = ImageNtHeader(hModule);

		IMAGE_SECTION_HEADER* pSectionHdr = (IMAGE_SECTION_HEADER*)(pNtHdr + 1);
		char* name = (char*)pSectionHdr->Name;
		return name;
	}
}