// RESTORED BY XSPY
#include "windows.h"
#include <iostream>
#include <iomanip>
#include <cstdio>
#include <cstdint>
#include <vector>
#include <map>
#include <chrono>
#include <stdarg.h>
#include <string>

#include "dumper.h"
#include "memory.h"
#pragma comment(lib, "dbghelp")

typedef uint32_t DUMPER; //meme

void mainDumper() {
	DWORD consoleOldProtect;
	VirtualProtect(FreeConsole, 1, PAGE_EXECUTE_READWRITE, &consoleOldProtect);
	*(UINT*)FreeConsole = 0xC2;
	AllocConsole();
	freopen("CONOUT$", "w", stdout);
	freopen("CONIN$", "r", stdin);
	SetConsoleTitle(TEXT("\Local\ [PROCESS] -> RobloxPlayerBeta.exe (DUMP)"));
	std::cout << str_format("%s: %p\n", "text", Memory::getSegmentAddr(".text"));
	std::cout << str_format("%s: %p\n", "data", Memory::getSegmentAddr(".data"));
	std::cout << str_format("%s: %p\n", "rdata", Memory::getSegmentAddr(".rdata");
	std::cout << str_format("%s: %p\n", "vmp0", Memory::getSegmentAddr(".vmp0"));
	std::cout << str_format("%s: %p\n", "vmp1", Memory::getSegmentAddr(".vmp1"));
	std::cout << str_format("%s: %p\n", "zero", Memory::getSegmentAddr(".zero"));

	DUMPER isdst = uDUMP::GetStringSubLoc("isdst");
	DUMPER cyclic = uDUMP::GetStringSubLoc("tables cannot be cyclic");
	DUMPER math = uDUMP::GetStringSubLoc("math");
	DUMPER module = uDUMP::GetStringSubLoc("Module code did not return exactly one value");
	DUMPER syntaxerror = uDUMP::GetStringSubLoc("syntax error: %s");
	DUMPER string = uDUMP::GetStringSubLoc("string slice too long");
	DUMPER running = uDUMP::GetStringSubLoc("Running Script \"%s\"");

	/* SIG SCANS */ //They pretty much have been static for a while and rarely break, so they should work without any problems.
	DUMPER Address_Deserializer = Memory::FindPattern((DWORD)GetModuleHandleA("RobloxPlayerBeta.exe"), 0xF00000, (PBYTE)"\x55\x8B\xEC\x6A\xFF\x68\x00\x00\x00\x00\x64\xA1\x00\x00\x00\x00\x50\x64\x89\x25\x00\x00\x00\x00\x81\xEC\x00\x00\x00\x00\x56\x57\x8B\x7D\x10\xC7\x45", (char*)"xxxxxx????xx????xxxx????xx????xxxxxxx");
	DUMPER luaF_newproto = Memory::FindPattern((DWORD)GetModuleHandleA("RobloxPlayerBeta.exe"), 0xF00000, (PBYTE)"\x55\x8B\xEC\x57\x6A\x54", (char*)"xxxxxx"); // Gonna look over memory once again and dump the structs later
	//END OF SIG SCANS//

	/* isdst */
	DUMPER lua_pushboolean = uDUMP::RETRIEVE(isdst, 25);
	DUMPER luaL_optlstring = uDUMP::RETRIEVE(isdst, 1);
	DUMPER lua_type = uDUMP::RETRIEVE(isdst, 2);
	DUMPER lua_setfield = uDUMP::RETRIEVE(isdst, 26);
	DUMPER lua_pushinteger = uDUMP::RETRIEVE(isdst, 23);
	DUMPER lua_createtable = uDUMP::RETRIEVE(isdst, 8);
	DUMPER lua_pushnil = uDUMP::RETRIEVE(isdst, 33);
	DUMPER lua_settop = uDUMP::RETRIEVE(isdst, 38);
	DUMPER lua_tointeger = uDUMP::RETRIEVE(isdst, 41);
	DUMPER lua_getfield = uDUMP::RETRIEVE(isdst, 43);
	DUMPER luaL_addlstring = uDUMP::RETRIEVE(isdst, 30);
	DUMPER lua_isnumber = uDUMP::RETRIEVE(isdst, 48);
	DUMPER lua_toboolean = uDUMP::RETRIEVE(isdst, 66);

	/* GETFIELD SUB'S */
	DUMPER index2addr = uDUMP::RETRIEVE(lua_getfield, 1);
	DUMPER luaS_newlstr = uDUMP::RETRIEVE(lua_getfield, 2);
	DUMPER luaV_gettable = uDUMP::RETRIEVE(lua_getfield, 3);

	/* CYCLIC */
	DUMPER lua_topointer = uDUMP::RETRIEVE(cyclic, 18);

	/* MODULE */
	DUMPER luaL_ref = uDUMP::RETRIEVE(module, 4);

	/* MATH */
	DUMPER lua_pushnumber = uDUMP::RETRIEVE(math, 2);

	/* SYNTAX ERR */
	DUMPER lua_newthread = uDUMP::RETRIEVE(syntaxerror, 6);
	DUMPER lua_rawgeti = uDUMP::RETRIEVE(syntaxerror, 13);

	/* STRING SLICE */
	DUMPER luaL_checkoption = uDUMP::RETRIEVE(string, 4);
	DUMPER luaL_checklstring = uDUMP::RETRIEVE(string, 1);
	DUMPER lua_gettop = uDUMP::RETRIEVE(string, 7);

	/* RUNNING SCRIPT */
	DUMPER random = uDUMP::RETRIEVE(running, 13); // "Unable to create a newthread for %s" theory of grabbing the lstate offsets straight from there (extremely stupid)

	/* OFFSETS */
	int SCRIPT_OFF = uDUMP::getOffSet(uDUMP::OpNum(0x83, running, 23));
	Console::Output(str_format("(OFFSET) %s: %d\n", "SCRIPT ENV", SCRIPT_OFF), OUTPUTTYPE::_ADD);

	int ENV_OFF = uDUMP::getOffSet(uDUMP::OpNum(0x2B, index2addr, 4));
	Console::Output(str_format("(OFFSET) %s: %d\n", "ENV", ENV_OFF), OUTPUTTYPE::_ADD);
	int TOP_OFF = uDUMP::getOffSet(uDUMP::OpNum(0x8B, lua_gettop, 3));
	Console::Output(str_format("(OFFSET) %s: %d\n", "TOP", TOP_OFF), OUTPUTTYPE::_ADD);
	int BASE_OFF = uDUMP::getOffSet(uDUMP::OpNum(0x2B, lua_gettop, 1));
	Console::Output(str_format("(OFFSET) %s: %d\n", "BASE", BASE_OFF), OUTPUTTYPE::_ADD);

	std::cout << "lua_newthread: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_newthread) << std::endl;
	std::cout << "lua_pushboolean: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_pushboolean) << std::endl;
	std::cout << "lua_type: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_type) << std::endl;
	std::cout << "lua_getfield: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_getfield) << std::endl;
	std::cout << "lua_setfield: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_setfield) << std::endl;
	std::cout << "lua_pushinteger: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_pushinteger) << std::endl;
	std::cout << "lua_createtable: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_createtable) << std::endl;
	std::cout << "lua_pushnil: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_pushnil) << std::endl;
	std::cout << "lua_settop: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_settop) << std::endl;
	std::cout << "lua_tointeger: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_tointeger) << std::endl;
	std::cout << "lua_isnumber: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_isnumber) << std::endl;
	std::cout << "lua_toboolean: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_toboolean) << std::endl;
	std::cout << "lua_topointer: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_topointer) << std::endl;
	std::cout << "lua_pushnumber: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_pushnumber) << std::endl;
	std::cout << "lua_rawgeti: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_rawgeti) << std::endl;
	std::cout << "luaS_newlstr: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(luaS_newlstr) << std::endl;
	std::cout << "luaV_gettable: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(luaV_gettable) << std::endl;
	std::cout << "luaL_optlstring: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(luaL_optlstring) << std::endl;
	std::cout << "luaL_addlstring: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(luaL_addlstring) << std::endl;
	std::cout << "luaL_ref: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(luaL_ref) << std::endl;
	std::cout << "luaL_checkoption: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(luaL_checkoption) << std::endl;
	std::cout << "luaL_checklstring: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(luaL_checklstring) << std::endl;
	std::cout << "lua_gettop: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(lua_gettop) << std::endl;
	std::cout << "deserializer: " << "0x" << unformat(Address_Deserializer) << std::endl;
	std::cout << "index2adr: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(index2addr) << std::endl;
	std::cout << "test: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(random) << std::endl;
	std::cout << "luaF_newproto: " << std::hex << std::setw(2) << std::setfill('0') << "0x" << unformat(luaF_newproto) << std::endl;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved) {
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
		CreateThread(NULL, NULL, (LPTHREAD_START_ROUTINE)mainDumper, NULL, NULL, NULL);
	return TRUE;
}