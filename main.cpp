#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <iostream>
#include <vector>
#include <cstdlib> 
#include <psapi.h>
#include <algorithm> 
#include <sstream>
using namespace std;



// 列出所有进程
void ListAllProcesses() {
    // 获取所有进程的 PID
    DWORD processIds[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(processIds, sizeof(processIds), &cbNeeded)) {  std::cerr << "无法获取进程列表" << std::endl; return; };
    cProcesses = cbNeeded / sizeof(DWORD);

    // 遍历所有进程的 PID
    for (unsigned int i = 0; i < cProcesses; i++) {
        DWORD pid = processIds[i];
        if (pid == 0) continue;
        wchar_t processName[MAX_PATH] = L"<unknown>";
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);

        if (hProcess != nullptr) {
            HMODULE h_mod;
            DWORD cbNeeded;
            if (EnumProcessModules(hProcess, &h_mod, sizeof(h_mod), &cbNeeded)) { GetModuleBaseNameW(hProcess, h_mod, processName, sizeof(processName) / sizeof(wchar_t)); };
            CloseHandle(hProcess);
        };

        if (_wcsicmp(processName, L"<unknown>") != 0) {  std::wcout << L"PID: " << pid << L", \t\t Name: " << processName << std::endl;  };
    };
};


// 获取指定进程名的进程ID
DWORD GetProcessIdByName(const std::string& processName) {
    // 创建进程快照
    const HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) { std::cerr << "创建进程快照失败。" << std::endl; return 0; };

    // 定义进程信息结构体
    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    // 遍历所有进程
    if (Process32First(hSnapshot, &pe)) {
        do { if (processName == pe.szExeFile) { 
            CloseHandle(hSnapshot);  
            std::cout << "\n" << processName << " 的进程 ID 是: " << pe.th32ProcessID << "\n" << std::endl;
            return pe.th32ProcessID;
        }; } 
        while (Process32Next(hSnapshot, &pe));
    };

    // 如果未找到匹配的进程，关闭句柄并返回0
    CloseHandle(hSnapshot);
    return 0;
};


// 扫描进程内存并查找指定值
std::vector<uintptr_t> ScanProcessMemory(const DWORD processID, const int targetValue) {
    std::vector<uintptr_t> addresses;  // 用于存储内存地址

    // 打开目标进程，获得读取内存的权限
    const HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, processID);
    if (hProcess == NULL) { std::cerr << "无法打开进程！" << std::endl; return addresses; };

    // 定义内存信息结构体
    MEMORY_BASIC_INFORMATION mbi;
    unsigned char* addr = nullptr;
    unsigned char* buffer = nullptr;

    // 扫描整个进程的内存空间
    while (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.State == MEM_COMMIT && mbi.Protect != PAGE_NOACCESS) {
            // 只在需要时分配缓冲区
            if (buffer == nullptr || mbi.RegionSize > _msize(buffer)) { delete[] buffer;  buffer = new unsigned char[mbi.RegionSize]; };

            SIZE_T bytesRead = 0;
            if (ReadProcessMemory(hProcess, addr, buffer, mbi.RegionSize, &bytesRead)) {
                for (SIZE_T i = 0; i < bytesRead - sizeof(targetValue); ++i) {
                    int value = *reinterpret_cast<int*>(buffer + i);
                    if (value == targetValue) { addresses.push_back(reinterpret_cast<uintptr_t>(addr + i)); };
                };
            };
        };
        addr += mbi.RegionSize;
    };

    // 清理资源
    delete[] buffer;
    CloseHandle(hProcess);
    return addresses;
};


// 修改内存值
bool ModifyMemory(HANDLE hProcess, uintptr_t addr, void* newData, size_t dataSize) {
    MEMORY_BASIC_INFORMATION mbi;

    if (VirtualQueryEx(hProcess, (LPCVOID)addr, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // 尝试更改内存保护
        DWORD oldProtect = mbi.Protect;
        if (oldProtect == PAGE_READONLY || oldProtect == PAGE_EXECUTE_READ) {
            DWORD tempProtect;
            if (!VirtualProtectEx(hProcess, (LPVOID)addr, dataSize, PAGE_READWRITE, &tempProtect)) { std::cerr << "无法更改内存保护，错误码：" << GetLastError() << std::endl; return false; };
        };

        // 写入新数据
        if (!WriteProcessMemory(hProcess, (LPVOID)addr, newData, dataSize, NULL)) {
            std::cerr << "写入内存失败，错误码：" << GetLastError() << std::endl;
            if (oldProtect != mbi.Protect) { VirtualProtectEx(hProcess, (LPVOID)addr, dataSize, oldProtect, &mbi.Protect); };
            return false;
        };

        // 恢复原来的内存保护
        if (oldProtect != mbi.Protect) { VirtualProtectEx(hProcess, (LPVOID)addr, dataSize, oldProtect, &mbi.Protect); };
        return true;
    };

    std::cerr << "无法查询内存信息，错误码：" << GetLastError() << std::endl;
    return false;
};


// 修改内存数据
void SetData(const DWORD pid, const std::vector<uintptr_t> address) {
    const HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION, FALSE, pid);
    
    int newData;
    cout << "请输入要修改的数据: ";
    cin >> newData;

    // 循环修改内存数据address
    for (auto addr : address) { if (!ModifyMemory(hProcess, addr, &newData, sizeof(newData))) { std::cout << "内存修改失败！" << std::endl; }; };

    std::cout << "修改完成！\n" << std::endl;
    CloseHandle(hProcess); // 关闭句柄
};


// 循环扫描并修改
std::vector<uintptr_t> Start(const DWORD pid, const int value) {
    // 输出进程名和要查找的值
    int targetValue = value;
    std::vector<uintptr_t> temp = ScanProcessMemory(pid, targetValue); 

    // 输出内存地址
    if (temp.size() == 0) return temp;
    int count = 0;

    // 循环查找
    while (true) { 
        const int size = temp.size();

        if (size == 1 || count > 1) {  
            std::cout << "\n找到了目标值: [" << targetValue << "]" << std::endl; break;
            for (auto addr : temp) { std::cout << "内存地址: [" << addr << "]" << std::endl; };
        };

        if (size == 0) {  std::cout << "未找到目标值的内存地址。" << "\n" << std::endl; return temp; };
        
        cout << "剩余[ " << size << " ], 正在筛选内存地址，请更换目标值: ";
        cin >> targetValue;

        std::vector<uintptr_t> old = ScanProcessMemory(pid, targetValue);
        std::sort(temp.begin(), temp.end());
        std::sort(old.begin(), old.end());
        std::vector<uintptr_t> intersection;
        std::set_intersection(temp.begin(), temp.end(), old.begin(), old.end(), std::back_inserter(intersection));
        temp = intersection;

        if (temp.size() == size) { count++; };
    };

    // 修改内存数据
    SetData(pid, temp);
    return temp;
};


// 获取进程ID
DWORD GetPid() {
    // 接收进程名
    string processName;
    std::cout << "请输入【进程名】: ";
    std::cin >> processName;

    // 获取进程ID，如果进程名不存在，则返回0
    const DWORD pid = GetProcessIdByName(processName);
    if (pid == 0) { std::cerr << "未找到进程。" << std::endl; return 0; };

    // 返回进程ID
    return pid;
};


// 通过进程名和目标值修改内存数据
void ChooseOne() {
    // 接收目标值
    int value;
    std::cout << "请输入【目标值】: ";
    std::cin >> value;

    // 接收进程ID，如果进程ID为0，则返回
    const DWORD pid = GetPid();
    if (pid == 0) return;

    // 开始查找内存地址，如果未找到，则返回
    const std::vector<uintptr_t> address = Start(pid, value);
    if (address.size() == 0) return;

    // 循环修改内存数据
    while(true) { SetData(pid, address); };
};


// 通过进程名和内存地址修改内存数据
void ChooseTow() {
    // 接收内存地址
    uintptr_t value;
    std::cout << "请输入【内存地址】: ";
    std::cin >> value;

    std::vector<uintptr_t> address = { value };

    // 接收进程ID，如果进程ID为0，则返回
    const DWORD pid = GetPid();
    if (pid == 0) return;

    // 循环修改内存数据
    while(true) { SetData(pid, address); };
};


// 菜单
void Menu() {
    // 输出菜单
    std::cout << "\n1 -> 列出当前所有进程 \n2 -> 通过【目标值】修改内存数据 \n3 -> 通过【内存地址】修改内存数据\n\n请选择对应模式:  ";
    int choice;
    std::cin >> choice;

    // 根据选择执行对应函数
    switch (choice) {
        case 1: ListAllProcesses(); break;
        case 2: ChooseOne(); break;
        case 3: ChooseTow(); break;
        default: system("cls");
    };
};


int main() {
    // 设置编码
    SetConsoleOutputCP(CP_UTF8); 
    std::cout << "\n欢迎使用内存修改器!" << std::endl;

    // 循环菜单
    while (true) { Menu(); };
    return 0;
};
