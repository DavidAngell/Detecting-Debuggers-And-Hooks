#define _CRT_SECURE_NO_WARNINGS

#pragma comment(lib, "ntdll.lib")
#include <phnt_windows.h>
#include <phnt.h>

#include <cstdint>
#include <iostream>
#include <string>

void CheckIsDebuggerPresent() {
    BOOL bIsDebuggerPresent = IsDebuggerPresent();
    if (bIsDebuggerPresent) {
        std::cout << "CheckIsDebuggerPresent: " << "Present" << std::endl;
    } else {
        std::cout << "CheckIsDebuggerPresent: " << "Not Present" << std::endl;
    }
}

void CheckCheckRemoteDebuggerPresent() {
    BOOL bIsDebuggerPresent;
    HANDLE hProcess = NtCurrentProcess();
    CheckRemoteDebuggerPresent(hProcess, &bIsDebuggerPresent);
    if (bIsDebuggerPresent) {
        std::cout << "CheckCheckRemoteDebuggerPresent: " << "Present" << std::endl;
    } else {
        std::cout << "CheckCheckRemoteDebuggerPresent: " << "Not Present" << std::endl;
    }
}

void CheckNtQueryInformationProcessProcessDebugPort() {
    DWORD_PTR dwProcessDebugPort = 0;
    DWORD dwReturned;
    NTSTATUS status = NtQueryInformationProcess(
        NtCurrentProcess(),
        PROCESSINFOCLASS::ProcessDebugPort,
        &dwProcessDebugPort,
        sizeof(DWORD_PTR),
        &dwReturned);

    if (NT_SUCCESS(status)) {
        if (dwProcessDebugPort) {
            std::cout << "CheckNtQueryInformationProcessProcessDebugPort: " << "Present" << std::endl;
        } else {
            std::cout << "CheckNtQueryInformationProcessProcessDebugPort: " << "Not Present" << std::endl;
        }
    } else {
        std::cout << "CheckNtQueryInformationProcessProcessDebugPort: " << "Error " << std::hex << status << std::endl;
    }
}

void CheckNtQueryInformationProcessProcessDebugFlags() {
    DWORD dwProcessDebugFlags = 0;
    DWORD dwReturned;
    NTSTATUS status = NtQueryInformationProcess(
        NtCurrentProcess(),
        PROCESSINFOCLASS::ProcessDebugFlags,
        &dwProcessDebugFlags,
        sizeof(DWORD),
        &dwReturned);

    if (NT_SUCCESS(status)) {
        if (dwProcessDebugFlags == 0) {
            std::cout << "CheckNtQueryInformationProcessProcessDebugFlags: " << "Present" << std::endl;
        } else {
            std::cout << "CheckNtQueryInformationProcessProcessDebugFlags: " << "Not Present" << std::endl;
        }
    } else {
        std::cout << "CheckNtQueryInformationProcessProcessDebugFlags: " << "Error " << std::hex << status << std::endl;
    }
}

void CheckNtQueryInformationProcessProcessDebugObjectHandle() {
    HANDLE hDebugObject = nullptr;
    NTSTATUS status = NtQueryInformationProcess(
        NtCurrentProcess(),
        PROCESSINFOCLASS::ProcessDebugObjectHandle,
        &hDebugObject,
        sizeof(HANDLE),
        nullptr);


    if (NT_SUCCESS(status) && hDebugObject) {
        std::cout << "CheckNtQueryInformationProcessProcessDebugObjectHandle: " << "Present" << std::endl;
    } else {
        std::cout << "CheckNtQueryInformationProcessProcessDebugObjectHandle: " << "Not Present" << std::endl;
    }
}

// Checks for the presence of a kernel debugger
void CheckNtQuerySystemInformation() {
    SYSTEM_KERNEL_DEBUGGER_INFORMATION SystemInfo;
    NTSTATUS status = NtQuerySystemInformation(
        SYSTEM_INFORMATION_CLASS::SystemKernelDebuggerInformation,
        &SystemInfo,
        sizeof(SystemInfo),
        NULL);

    if (NT_SUCCESS(status)) {
        if (SystemInfo.KernelDebuggerEnabled && !SystemInfo.KernelDebuggerNotPresent) {
            std::cout << "CheckNtQuerySystemInformation: " << "Present" << std::endl;
        } else {
            std::cout << "CheckNtQuerySystemInformation: " << "Not Present" << std::endl;
        }
    } else {
        std::cout << "CheckNtQuerySystemInformation: " << "Error " << std::hex << status << std::endl;
    }
}

// When a program is not being debugged, breakpoint instructions cause an
// EXCEPTION_BREAKPOINT, so if an exception is not thrown, a debugger is present.
void CheckWithBreakpoint() {
    bool bIsDebuggerPresent;

    __try {
        __debugbreak();
        bIsDebuggerPresent = true;
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        bIsDebuggerPresent = false;
    }

    if (bIsDebuggerPresent) {
        std::cout << "CheckWithBreakpoint: " << "Present" << std::endl;
    } else {
        std::cout << "CheckWithBreakpoint: " << "Not Present" << std::endl;
    }
}

void CheckHardwareBreakpointPresent() {
    CONTEXT context = {};
    context.ContextFlags = CONTEXT_DEBUG_REGISTERS;
    HANDLE hThread = NtCurrentThread();
    NTSTATUS status = NtGetContextThread(hThread, &context);

    if (!NT_SUCCESS(status)) {
        std::cout << "DetectHardwareBreakpoints: " << "Error " << std::hex << status << std::endl;
    }

    if ((context.Dr0) || (context.Dr1) || (context.Dr2) || (context.Dr3)) {
        std::cout << "CheckHardwareBreakpointPresent: " << "Present" << std::endl;
    } else {
        std::cout << "CheckHardwareBreakpointPresent: " << "Not Present" << std::endl;
    }
}

void CheckSoftwareBreakpointPresentAt(void* pMemory, size_t ullSizeToCheck) {
    const UINT8 OpcodeInt3 = 0xCC;
    const UINT8 OpcodeInt1 = 0xF1;
    const UINT16 OpcodeLongInt3 = 0x03CD;
    const UINT16 OpcodeUd2 = 0x0B0F;

    bool bIsSoftwareBreakpointPresent = false;
    UINT8* pTemp = (UINT8*)pMemory;
    for (size_t i = 0; i < ullSizeToCheck; i++) {
        UINT8 CurrentInstructionU8 = pTemp[i];
        UINT16 CurrentInstructionU16 = *((UINT16*)(pTemp + i));
        if (CurrentInstructionU8 == OpcodeInt3
            || CurrentInstructionU8 == OpcodeInt1
            || CurrentInstructionU16 == OpcodeLongInt3
            || CurrentInstructionU16 == OpcodeUd2) {
            bIsSoftwareBreakpointPresent = true;
            break;
        }
    }

    if (bIsSoftwareBreakpointPresent) {
        std::cout << "CheckSoftwareBreakpointPresentAt: " << "Present" << std::endl;
    } else {
        std::cout << "CheckSoftwareBreakpointPresentAt: " << "Not Present" << std::endl;
    }
}

int main() {
    // Detecting debuggers
    CheckIsDebuggerPresent();
    CheckCheckRemoteDebuggerPresent();
    CheckNtQueryInformationProcessProcessDebugPort();
    CheckNtQueryInformationProcessProcessDebugFlags();
    CheckNtQueryInformationProcessProcessDebugObjectHandle();
    CheckNtQuerySystemInformation();
    CheckWithBreakpoint();

    // Spacing
    std::cout << std::endl;

    // Detecting breakpoints
    CheckHardwareBreakpointPresent();
    CheckSoftwareBreakpointPresentAt(&CheckIsDebuggerPresent, 8);
}