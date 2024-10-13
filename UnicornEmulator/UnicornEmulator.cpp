#include <unicorn/unicorn.h>
#include <iostream>
#include <Windows.h>
#include <intrin.h>
#include <TlHelp32.h>
#include <vector>

// Raw function to enter emulation
/*
    TODO:
        Make raw func, and use VirtualQuery to query every address and update registers.

        Code flow:
            Call func with args:
                Intermediate func which captures context and calls internal func
                Internal func begins emulation with context, and a copied stack
                Returns
                Stack get copied.
                UD? Indeed.
*/

struct MemoryInfo {
    std::uintptr_t baseAddress = 0;
    std::uintptr_t length = 0;
    bool isValid = false;
};

void QueryMemoryInfo(std::uintptr_t address, MemoryInfo& result) {
    MEMORY_BASIC_INFORMATION MBI{};

    if (!VirtualQuery((PVOID)address, &MBI, sizeof(MBI)))
        result.isValid = false;
    else
    {
        if (MBI.Protect & (PAGE_NOACCESS | PAGE_GUARD))
            result.isValid = false;
        else
        {
            result.baseAddress = (std::uintptr_t)MBI.BaseAddress;
            result.length = MBI.RegionSize;
            result.isValid = true;
        }
    }
}

static bool hook_mem_unmapped(uc_engine* uc, uc_mem_type type, uint64_t address,
    int size, uint64_t value, void* cpu);

static void hook_mem_access(uc_engine* uc, uc_mem_type type, uint64_t address,
    int size, uint64_t value, void* ud);

// Bridge between my memory and game memory
struct MappedAllocation {
    std::uintptr_t begin;
    std::uintptr_t end;

    bool contains(std::uintptr_t addr) {
        return (begin <= addr) && (end >= addr);
    }
};

// Keeps track of cheat pages so when one is written to, then it will be updated to the game
struct EmulatedBridge {
    HANDLE hProcess;
    std::vector<MappedAllocation> mappedAllocations{};

    void SetupBridge(DWORD pid) {
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    }

    bool IsMappedMemory(std::uintptr_t address) {
        for (MappedAllocation& MA : mappedAllocations) {
            if (MA.contains(address))
                return true;
        }

        return false;
    }

    // Maps a page of memory into our process from the game
    void MapMemory(uc_engine* uc, std::uintptr_t address) {
        MappedAllocation newMapping{};
        std::uintptr_t alignedAddress = address & ~0xFFFULL;
        
        void* newPage = VirtualAlloc(0, 0x1000, MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE);

        // Write memory from game into the page
        ReadProcessMemory(hProcess, (PVOID)alignedAddress, newPage, 0x1000, nullptr);

        // Map into the emulator
        uc_mem_map_ptr(uc, alignedAddress, 0x1000, UC_PROT_ALL, newPage);

        // Store in mapped cache
        newMapping.begin = alignedAddress;
        newMapping.end = alignedAddress + 0x1000;
        mappedAllocations.push_back(newMapping);
    }
};

struct EmulatedCPU {
    EmulatedBridge bridge;
    uc_engine* uc;
    std::uintptr_t rax, rbx, rcx, rdx, rsi, rdi;
    std::uintptr_t rbp, rsp, rip;
    std::uintptr_t rflags;
    std::uintptr_t fs, gs;

    M128A xmm0, xmm1, xmm2, xmm3, xmm4, xmm5, xmm6, xmm7, xmm8,
        xmm9, xmm10, xmm11, xmm12, xmm13, xmm14, xmm15, xmm16, xmm17, xmm18, xmm19, xmm20,
        xmm21, xmm22, xmm23, xmm24, xmm25, xmm26, xmm27, xmm28, xmm29, xmm30, xmm31, xmm32;

    void CreateBridge(DWORD pid) {
        bridge.SetupBridge(pid);
    }
    
    // Map memory 1:1 with host
    bool MapCorrespondingMemory(std::uintptr_t address) {
        MemoryInfo info{};
        QueryMemoryInfo(address, info);

        // Not all memory will be valid!
        if (!info.isValid)
            return false;

        info.baseAddress = address & ~0xFFFULL; // Align
        info.length = 0x1000; // 1 page

        if (uc_mem_map_ptr(uc, info.baseAddress, info.length, UC_PROT_ALL, (void*)info.baseAddress) != UC_ERR_OK) {
            std::printf("Failed to map: 0x%p (0x%p bytes)\n", info.baseAddress, info.length);
            return false;
        }
    }

    void SetupContext() {
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_ALL;
        GetThreadContext(GetCurrentThread(), &ctx);

        if (uc_open(UC_ARCH_X86, UC_MODE_64, &uc) != UC_ERR_OK) {
            std::printf("Failed to make engine!\n");
            return;
        }

        rax = ctx.Rax;
        rbx = ctx.Rbx;
        rcx = ctx.Rcx;
        rdx = ctx.Rdx;
        rsi = ctx.Rsi;
        rdi = ctx.Rdi;

        MemoryInfo memoryInfo{};
        QueryMemoryInfo(ctx.Rsp, memoryInfo);

        if (!memoryInfo.isValid) {
            std::printf("Invalid stack!\n");
            return;
        }

        // Get offset of RSP into the stack
        std::uintptr_t offsetRSP = ctx.Rsp - memoryInfo.baseAddress;

        // Get offset of RBP into the stack
        std::uintptr_t offsetRBP = ctx.Rbp - memoryInfo.baseAddress;

        std::printf("Offset RSP: 0x%p | Offset RBP: 0x%p\n", offsetRSP, offsetRBP);

        std::uintptr_t topStack = (std::uintptr_t)(VirtualAlloc(0, 0x6000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        std::uintptr_t bottomStackCopy = (topStack + 0x6000) - memoryInfo.length;

        // Clone stack
        std::memcpy((void*)bottomStackCopy, (void*)memoryInfo.baseAddress, memoryInfo.length);

        rsp = bottomStackCopy + offsetRSP;
        rbp = bottomStackCopy + offsetRBP;

        rflags = ctx.EFlags;

        // Windows x64 only uses these 2 segments, in x86 you need more emulation.
        fs = _readfsbase_u64();
        gs = _readgsbase_u64();

        xmm0 = ctx.Xmm0;
        xmm1 = ctx.Xmm1;
        xmm2 = ctx.Xmm2;
        xmm3 = ctx.Xmm3;
        xmm4 = ctx.Xmm4;


    }

    std::uintptr_t BeginEmulation(std::uintptr_t codeToExecute) {
        if (!uc) {
            std::printf("Cannot emulate virtual CPU without uc!\n");
            return 0;
        }

        int pRawRegs[] = {
            UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX, UC_X86_REG_RSI, UC_X86_REG_RDI,
            UC_X86_REG_RBP, UC_X86_REG_RSP, UC_X86_REG_RFLAGS, UC_X86_REG_FS_BASE, UC_X86_REG_GS_BASE,

            UC_X86_REG_XMM0, UC_X86_REG_XMM1, UC_X86_REG_XMM2, UC_X86_REG_XMM3, UC_X86_REG_XMM4
        };

        void* pRawValues[] = {
            &rax, &rbx, &rcx, &rdx, &rsi, &rdi,
            &rbp, &rsp, &rflags, &fs, &gs,

            &xmm0, &xmm1, &xmm2, &xmm3, &xmm4
        };

        if (uc_reg_write_batch(uc, pRawRegs, pRawValues, sizeof(pRawRegs) / sizeof(pRawRegs[0]))
            != UC_ERR_OK) {
            std::printf("Failed to write registers!\n");
            return 0;
        }

        // Stub to enter into code
        static unsigned char enterStub[] = { 0x48, 0xB8, 0x22, 0x11, 0xEE, 0xDD, 0xCC, 0xBB, 0xAA, 0x00, 0xFF, 0xD0, 0x90 };
        *(std::uintptr_t*)(&enterStub[2]) = codeToExecute;

        uc_hook myHook, myOtherHook{};
        if (uc_hook_add(uc, &myHook, UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED | UC_HOOK_MEM_FETCH_UNMAPPED,
            hook_mem_unmapped, this, 1, 0) != UC_ERR_OK) {
            std::printf("Failed to add paging hook!\n");
            return 0;
        }

        if (uc_hook_add(uc, &myOtherHook, UC_HOOK_MEM_WRITE,
            hook_mem_access, this, 1, 0) != UC_ERR_OK) {
            std::printf("Failed to add write watcher hook!\n");
            return 0;
        }

        uc_err err = uc_emu_start(uc, (uintptr_t)enterStub, (uintptr_t)enterStub + sizeof(enterStub) - 1, 1000000, 0);
        if (err != UC_ERR_OK) {
            std::printf("Emulation failed!\n");
            std::printf("Error: %d\n", err);
        }

        uc_hook_del(uc, myHook);
        uc_hook_del(uc, myOtherHook);

        if (uc_reg_read_batch(uc, pRawRegs, pRawValues, sizeof(pRawRegs) / sizeof(pRawRegs[0]))
            != UC_ERR_OK) {
            std::printf("Failed to read registers!\n");
            return 0;
        }

        return rax;
    }

    // First argument
    void SetRCX(uintptr_t argRcx) {
        rcx = argRcx;
    }
};

// This will get called when the program tries to access memory that isn't mapped in.
// First attempt to page it in from host, if it fails then
// try to page it from the game. If both fail, then exit vm.
static bool hook_mem_unmapped(uc_engine* uc, uc_mem_type type, uint64_t address,
    int size, uint64_t value, void* cpu)
{
    std::uintptr_t rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);

    std::printf("Exception occured at 0x%p\n", rip);
    switch (type) {
    default:
        // return false to indicate we want to stop emulation
        std::printf("Unknown error in unmapped handler!\n");
        return false;
    case UC_MEM_WRITE_UNMAPPED:
        std::printf("Attempt to WRITE at 0x%llx | Size: %u | Value: 0x%llx\n",
            address, size, value);
        break;
    case UC_MEM_READ_UNMAPPED:
        std::printf("Attempt to READ at 0x%llx | Size: %u\n",
            address, size);
        break;
    case UC_MEM_FETCH_UNMAPPED:
        std::printf("Attempt to FETCH at 0x%llx | Size: %u\n",
            address, size);
        break;
    }

    EmulatedCPU* pCPU = (EmulatedCPU*)cpu;

    // Attempt to load in address and continue
    if (!pCPU->MapCorrespondingMemory(address)) {
        std::printf("Mapping 0x%p from game.\n", address);
        pCPU->bridge.MapMemory(pCPU->uc, address);
    }

    // return true to indicate we want to continue
    return true;
}

// When it's a write we need to reflect changes to the game.
static void hook_mem_access(uc_engine* uc, uc_mem_type type, uint64_t address,
    int size, uint64_t value, void* cpu)
{
    if (type != UC_MEM_WRITE)
        return;

    std::uintptr_t rip = 0;
    uc_reg_read(uc, UC_X86_REG_RIP, &rip);

    std::printf("Exception occured at 0x%p\n", rip);
    std::printf("Writing 0x%llx to 0x%llx (%u bytes)\n",
        value, address, size);

    EmulatedCPU* pCPU = (EmulatedCPU*)cpu;
    if (pCPU->bridge.IsMappedMemory(address)) {
        std::printf("Game memory found! Updating...\n");
        
        // Write to game to keep ourselves in sync with game values.
        WriteProcessMemory(pCPU->bridge.hProcess, (PVOID)address, &value, size, nullptr);
    }
}

// Function I will emulate
int FunctionB(const char* b) {
    int output = 0;
    for (int i = 0; i < strlen(b); i++) {
        output += b[i];
    }

    return output;
}

int __declspec(noinline) MultiplyFunc(int input) {
    static int a = 42;
    a = FunctionB("Secret KEY") * 10;

    return a;
}

struct ProcessInfo
{
    bool isValid = false;
    DWORD pid = 0;
    std::uintptr_t processBase = 0;
};

ProcessInfo FindProcess(const char* name) {
    ProcessInfo outputInfo{};
    outputInfo.isValid = false;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);

    PROCESSENTRY32 process{};
    process.dwSize = sizeof(process);

    if (Process32First(hSnapshot, &process)) {
        do {
            if (!strcmp(process.szExeFile, name)) {
                outputInfo.pid = process.th32ProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &process));
    }

    CloseHandle(hSnapshot);

    hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, outputInfo.pid);
    MODULEENTRY32 currModule{};
    currModule.dwSize = sizeof(currModule);

    if (Module32First(hSnapshot, &currModule)) {
        do {
            if (!strcmp(currModule.szModule, name)) {
                outputInfo.processBase = (std::uintptr_t)currModule.modBaseAddr;
                outputInfo.isValid = true;
                break;
            }
        } while (Module32Next(hSnapshot, &currModule));
    }

    CloseHandle(hSnapshot);
    return outputInfo;
}

static std::uintptr_t TargetFunc = 0;
std::uintptr_t ReadGameValue() { // Called inside emulator so I can do jank shit!
    printf("CHEST LOADED!\n");
    return 69;
}

static std::uintptr_t gameBase = 0;
std::uintptr_t GetWaitingScripts() { // TODO: Add segment register to read game base
    std::uintptr_t scheduler = *(std::uintptr_t*)(gameBase + 0x5DC6B20);
    for (std::uintptr_t job = *(std::uintptr_t*)(scheduler + 0x198);
        job < *(std::uintptr_t*)(scheduler + 0x1A0); job += 16) {
        const char* jobName = (const char*)(*(std::uintptr_t*)job + 0x90);
        if (*(std::uintptr_t*)(*(std::uintptr_t*)job + 0xA0) >= 0x10)
            jobName = *(const char**)(jobName);

        if (!std::strcmp(jobName, "WaitingHybridScriptsJob"))
            return *(std::uintptr_t*)job;
    }

    return 0;
}

std::uintptr_t GetScriptContext(std::uintptr_t waitingScripts) {
    return *(std::uintptr_t*)(waitingScripts + 0x1F8);
}

// Calls game functions to get the lua state externally
std::uintptr_t GetLuaState(std::uintptr_t scriptContext) {
    std::uintptr_t input[2]{ 0 };
    std::uintptr_t input_2{ 0 };

    using GetLuaState_T = std::uintptr_t(__fastcall*)(std::uintptr_t SC, std::uintptr_t* input, std::uintptr_t* input2);
    GetLuaState_T GetLuaStateInternal = (GetLuaState_T)(gameBase + 0x0CAAB70);

    using DecryptState_T = std::uintptr_t(__fastcall*)(std::uintptr_t encrypted);
    DecryptState_T DecryptState = (DecryptState_T)(gameBase + 0x0A8C390);

    std::uintptr_t result = GetLuaStateInternal(scriptContext + 0x110, input, &input_2);
    return DecryptState(result + 0x88);
}

int main()
{
    ProcessInfo procInfo = FindProcess("RobloxPlayerBeta.exe");
    if (!procInfo.isValid) {
        std::printf("Failed to find process!\n");
        return 0;
    }

    gameBase = procInfo.processBase;

    std::printf("PID: %d | Base: 0x%p\n", procInfo.pid, procInfo.processBase);

    EmulatedCPU myCPU{};
    myCPU.CreateBridge(procInfo.pid); // Create memory bridge between processes
    myCPU.SetupContext(); // Setup this thread for emulation.


    // Enter emulator and get result back
    std::uintptr_t waitingScriptsJob = myCPU.BeginEmulation((std::uintptr_t)GetWaitingScripts);
    std::printf("WaitingScriptsJob: 0x%llx\n", waitingScriptsJob);

    myCPU.SetRCX(waitingScriptsJob);
    std::uintptr_t scriptContext = myCPU.BeginEmulation((std::uintptr_t)GetScriptContext);

    std::printf("Script Context: 0x%llx\n", scriptContext);

    myCPU.SetRCX(scriptContext);
    std::uintptr_t luaState = myCPU.BeginEmulation((std::uintptr_t)GetLuaState);

    std::printf("Lua state: 0x%llx\n", luaState);

    std::cin.get();
}