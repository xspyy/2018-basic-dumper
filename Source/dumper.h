// RESTORED BY XSPY
#pragma once
#include "memory.h"

#define format(x) (x - 0x400000 + (DWORD)GetModuleHandle(NULL))
#define unformat(x)( x + 0x400000 - (DWORD)GetModuleHandle(NULL))

std::string str_format(const std::string fmt, ...) {
	int size = ((int)fmt.size()) * 2 + 50;
	std::string str;
	va_list ap;
	while (1) {
		str.resize(size);
		va_start(ap, fmt);
		int n = vsnprintf((char*)str.data(), size, fmt.c_str(), ap);
		va_end(ap);
		if (n > -1 && n < size) {
			str.resize(n);
			return str;
		}
		if (n > -1)
			size = n + 1;
		else
			size *= 2;
	}
	return str;
}

namespace uDUMP {
	uintptr_t getOffSet(DWORD addr) {
		char* cAddr = (char*)addr;
		return cAddr[2];
	}

	uintptr_t GetCalling(DWORD CALL) {
		return (CALL + *(DWORD*)(CALL + 1)) + 5;
	}


	uintptr_t GetNextCall(DWORD from) {
		for (int i = 0; i < INT_MAX; i++) {
			if (*(BYTE*)(from + i) == 0xE8) {
				return from + i;
				break;
			}
		}
		return from;
	}

	uintptr_t GetCallNum(DWORD from, DWORD n) {
		int res = 0;
		for (int i = 0; i < INT_MAX; i++) {
			if (*(BYTE*)(from + i) == 0xE8) {
				res += 1;
				if (res == n) {
					return from + i;
					break;
				}
			}
		}
		return from;
	}

	uintptr_t OpNum(DWORD op, DWORD from, DWORD n) {
		int res = 0;
		for (int i = 0; i < INT_MAX; i++) {
			if (*(BYTE*)(from + i) == op) {
				res += 1;
				if (res == n) {
					return from + i;
					break;
				}
			}
		}
		return from;
	}

	uintptr_t RETRIEVE(DWORD from, DWORD n) {
		return GetCalling(GetCallNum(from, n));
	}

	uintptr_t GetFuncTop(DWORD a) {
		const char prol[3] = { 0x55, 0x8B, 0xEC };
		for (int i = a; i > INT_MIN; i -= 1) {
			if (memcmp(prol, (void*)i, sizeof(prol)) == 0) {
				return i;
			}
		}
	}

	uintptr_t GetFuncEnd(DWORD a) {
		const char prol[3] = { 0x55, 0x8B, 0xEC };
		for (int i = a; i < INT_MIN; i++) {
			if (memcmp(prol, (void*)i, sizeof(prol)) == 0) {
				return i;
			}
		}
	}

	uintptr_t GetFuncSize(DWORD a) {
		return GetFuncEnd(a) - GetFuncTop(a);
	}

	uintptr_t GetStringSubLoc(const char* c, int region = 0x400000, int dataRegion = Memory::getSegmentAddr(".rdata"), int _max = INT_MAX) {
		uintptr_t result = NULL;
		for (int i = dataRegion; i < _max; i = i + 1) {
			if (*(const char*)format(i) != NULL) {
				char* strloc = (char*)format(i);

				if (std::string(strloc) == std::string(c)) {
					result = format(i);
					break;
				}
			}
		}

		for (int i = region; i < _max; i++) {
			if (*(BYTE*)format(i) == 0x68 && *(DWORD*)format(i + 1) == result) {
				result = format(i);
				break;
			}
		}
		result = GetFuncTop(result);
		return result;

		for (int i = region; i < _max; i++) {
			if (*(BYTE*)format(i) == 0x68 && *(DWORD*)format(i + 1) == result) {
				result = format(i);
				break;
			}
		}
		result = GetFuncTop(result);
		return result;
	}


	uintptr_t GetCallByString(const char* c, int CALL_LOC = 1, int region = 0x400000, int dataRegion = Memory::getSegmentAddr(".rdata"), int _max = INT_MAX) {
		uintptr_t result = NULL;
		for (int i = dataRegion; i < _max; i = i + 1) {
			if (*(const char*)format(i) != NULL) {
				char* strloc = (char*)format(i);

				if (std::string(strloc) == std::string(c)) {
					//printf("Got str: %s\n", strloc);
					result = format(i);
					break;
				}
			}

		}
		for (int i = region; i < _max; i++) {
			if (*(BYTE*)format(i) == 0x68 && *(DWORD*)format(i + 1) == result) {
				result = format(i);
				break;
			}
		}
		result = GetFuncTop(result);
		result = GetCallNum(result, CALL_LOC);

		DWORD T_CALL = GetCalling(result);
		return T_CALL;
	}
}