#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>
#include <filesystem>
void ListDLLs(const std::string& directory, std::vector<std::string>& dlls) {
    for (const auto& entry : std::filesystem::directory_iterator(directory)) {
        if (entry.path().extension() == ".dll") {
            dlls.push_back(entry.path().filename().string());
        }
    }
}
DWORD GetProcessId(const std::wstring& processNameOrId) {
    try {
        DWORD processId = std::stoul(processNameOrId);
        return processId;
    }
    catch (std::invalid_argument&) {
    }
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(snapshot, &pe32)) {
        CloseHandle(snapshot);
        return 0;
    }
    do {
        if (processNameOrId == pe32.szExeFile) {
            CloseHandle(snapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(snapshot, &pe32));
    CloseHandle(snapshot);
    return 0; 
}
bool InjectDLL(const std::string& dllPath, DWORD processId) {
    HANDLE processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!processHandle) {
        std::cout << "failed to open process!" << std::endl;
        return false;
    }
    void* allocatedMemory = VirtualAllocEx(processHandle, nullptr, dllPath.size() + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!allocatedMemory) {
        std::cout << "failed to allocate memory in target process!" << std::endl;
        CloseHandle(processHandle);
        return false;
    }
    if (!WriteProcessMemory(processHandle, allocatedMemory, dllPath.c_str(), dllPath.size() + 1, nullptr)) {
        std::cout << "failed to write to process memory!" << std::endl;
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }
    HMODULE kernel32 = GetModuleHandleA("kernel32.dll");
    FARPROC loadLibraryAddr = GetProcAddress(kernel32, "LoadLibraryA");
    HANDLE threadHandle = CreateRemoteThread(processHandle, nullptr, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, allocatedMemory, 0, nullptr);
    if (!threadHandle) {
        std::cout << "failed to create remote thread!" << std::endl;
        VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
        CloseHandle(processHandle);
        return false;
    }
    WaitForSingleObject(threadHandle, INFINITE);
    VirtualFreeEx(processHandle, allocatedMemory, 0, MEM_RELEASE);
    CloseHandle(threadHandle);
    CloseHandle(processHandle);

    return true;
}
int main() {
    std::string dllDir;
    std::cout << "enter the directory to list DLLs from: ";
    std::getline(std::cin, dllDir);
    std::vector<std::string> dlls;
    ListDLLs(dllDir, dlls);
    std::cout << "available dlls:\n";
    for (size_t i = 0; i < dlls.size(); ++i) {
        std::cout << i + 1 << ": " << dlls[i] << std::endl;
    }
    int choice;
    std::cout << "enter the number of the dll to inject: ";
    std::cin >> choice;
    if (choice < 1 || choice > dlls.size()) {
        std::cout << "invalid choice!" << std::endl;
        return 1;
    }
    std::string dllPath = dllDir + "\\" + dlls[choice - 1];
    std::wstring processNameOrId;
    std::cout << "enter the process name (e.x. game.exe) or PID: ";
    std::wcin.ignore(); 
    std::getline(std::wcin, processNameOrId);
    DWORD processId = GetProcessId(processNameOrId);
    if (processId == 0) {
        std::cout << "process not found!" << std::endl;
        return 1;
    }
    if (InjectDLL(dllPath, processId)) {
        std::cout << "dll injected successfully!" << std::endl;
    }
    else {
        std::cout << "dll injection failed!" << std::endl;
    }
    return 0;
}
