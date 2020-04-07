#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>

HANDLE hProcess;
uintptr_t moduleBase, size;
int found, missed = 0;

void GetModule(const char* modName, DWORD procId) {
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, procId);
	if (hSnap != INVALID_HANDLE_VALUE) {
		MODULEENTRY32 modEntry;
		modEntry.dwSize = sizeof(modEntry);
		if (Module32First(hSnap, &modEntry)) {
			do {
				if (!strcmp(modEntry.szModule, modName)) {
					CloseHandle(hSnap);
					size = modEntry.modBaseSize;
					moduleBase = (uintptr_t)modEntry.modBaseAddr;
					return;
				}
			} while (Module32Next(hSnap, &modEntry));
		}
	}
}

template<typename T> T RPM(SIZE_T address) {
	T buffer; ReadProcessMemory(hProcess, (void*)address, &buffer, sizeof(T), nullptr);
	return buffer;
}

//https://guidedhacking.com/threads/external-signature-pattern-scan-issues.12618/?view=votes#post-73200
uintptr_t find_pattern(const char* pattern, const char* mask, uintptr_t begin, uintptr_t end, HANDLE hProc) {

	auto scan = [](const char* pattern, const char* mask, char* begin, unsigned int size) -> char* {
		size_t patternLen = strlen(mask);
		for (unsigned int i = 0; i < size - patternLen; i++) {
			bool found = true;
			for (unsigned int j = 0; j < patternLen; j++) {
				if (mask[j] != '?' && pattern[j] != *(begin + i + j)) {
					found = false;
					break;
				}
			}
			if (found) { return (begin + i); }
		}
		return nullptr;
	};

	uintptr_t match = NULL;
	SIZE_T bytesRead;
	DWORD oldprotect;
	char* buffer = nullptr;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	uintptr_t curr = begin;

	for (uintptr_t curr = begin; curr < end; curr += mbi.RegionSize) {
		if (!VirtualQueryEx(hProc, (void*)curr, &mbi, sizeof(mbi))) continue;
		if (mbi.State != MEM_COMMIT || mbi.Protect == PAGE_NOACCESS) continue;

		buffer = new char[mbi.RegionSize];

		if (VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, PAGE_EXECUTE_READWRITE, &oldprotect)) {
			ReadProcessMemory(hProc, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead);
			VirtualProtectEx(hProc, mbi.BaseAddress, mbi.RegionSize, oldprotect, &oldprotect);

			char* internalAddr = scan(pattern, mask, buffer, (unsigned int)bytesRead);

			if (internalAddr != nullptr) {
				//calculate from internal to external
				match = curr + (uintptr_t)(internalAddr - buffer);
				break;
			}
		}
	}
	delete[] buffer;
	return match;
}

//accepts
//"? C2 85 C0 7E ? 8B D0 E8"   and
//"?? C2 85 C0 7E ?? 8B D0 E8" and
//"* C2 85 C0 7E * 8B D0 E8"   and
//"** C2 85 C0 7E ** 8B D0 E8"
//https://guidedhacking.com/threads/universal-pattern-signature-parser.9588/
uintptr_t push_address(const char* sig) {
	char pattern[100];
	char mask[100];

	char lastChar = ' ';
	unsigned int j = 0;

	for (unsigned int i = 0; i < strlen(sig); i++) {
		if ((sig[i] == '?' || sig[i] == '*') && (lastChar != '?' && lastChar != '*')) {
			pattern[j] = mask[j] = '?';
			j++;
		}

		else if (isspace(lastChar)) {
			pattern[j] = lastChar = (char)strtol(&sig[i], 0, 16);
			mask[j] = 'x';
			j++;
		}
		lastChar = sig[i];
	}
	pattern[j] = mask[j] = '\0';

	auto current_address = find_pattern(pattern, mask, moduleBase, moduleBase + size, hProcess) + 0x3;
	
	if (current_address <= 0x5) {
		missed++;
		return 0x0;
	}

	found++;
	return current_address + RPM<int32_t>(current_address) + 4 - moduleBase;
}

int main() {
	HWND hWnd = FindWindowA(NULL, "Rainbow Six");
	DWORD dwPID; GetWindowThreadProcessId(hWnd, &dwPID);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, dwPID);
	GetModule("RainbowSix.exe", dwPID);

	//https://github.com/armvirus/r6-offset-dumper/blob/4102e1b689f4316f1ebfadcc383ee08d5b4fcf3f/main.cpp#L17
	printf("%s:\t\t\t0x%X\n", "GameManager",             push_address("48 8B 05 ? ? ? ? 8B 8E"));
	printf("%s:\t\t\t0x%X\n", "FovManager",              push_address("48 8B 05 ? ? ? ? F3 44 0F 10 91"));
	printf("%s:\t\t\t0x%X\n", "RoundManager",            push_address("48 8B 05 ? ? ? ? 8B 90 ? ? ? ? 83 3D"));
	printf("%s:\t\t\t0x%X\n", "GlowManager",             push_address("48 8B 0D ? ? ? ? 48 8B D7 E8 ? ? ? ? 48 85 C0"));
	printf("%s:\t\t\t0x%X\n", "ProfileManager",          push_address("48 8B 05 ? ? ? ? 33 D2 4C 8B 40 78"));
	printf("%s:\t\t\t0x%X\n", "VTMarker",                push_address("4C 8D 0D ? ? ? ? 48 ? ? ? 48 8D 8B ? ? ? ? 4C ? ? 48 8D ? ? ? ? ? E8"));
	printf("%s:\t\t\t0x%X\n", "NetworkManager",          push_address("48 8B 05 ? ? ? ? 48 85 C0 0F 84 ? ? ? ? 48 8B 88 ? ? ? ? 48 85 C9 0F 84 ? ? ? ? 4C 8B 8D"));
	printf("%s:\t0x%X\n",     "InstantAnimationManager", push_address("48 8B 05 ? ? ? ? 41 0F B6 F8 8B DA"));
	printf("%s:\t\t\t0x%X\n", "InputManager",            push_address("4C 8B 05 ? ? ? ? 41 80 78"));
	printf("%s:\t\t\t0x%X\n", "FreezeManager",           push_address("48 8B 05 ? ? ? ? 0F B6 48 61"));
	printf("Done! Found %d/%d.\n", found, found + missed);
	getchar();
}