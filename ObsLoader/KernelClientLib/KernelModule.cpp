#include "KernelModule.h"

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
enum MyKernelMessageType
{
    ReadRequest,
    WriteRequest,
    WriteFromLoaderRequest,
    GetModuleBaseAddressRequest,
    AllocRequest,
    CreateThreadRequest,
    PingRequest
};

struct MyKernelMessage
{
    MyKernelMessageType MessageType;
    NTSTATUS RequestStatus;
    union _Message
    {
        struct _ReadRequest
        {
            UINT64 UniqueProcessPid;	//PID of the target
            PVOID Source;				//Address in the target's address spce
            PVOID Destination;			//Addressin our address space
            UINT64 Length;				//Size of the copy(in bytes)
            SIZE_T BytesRead;			//Number of bytes read
        } ReadRequestMessage;

        struct _WriteRequest
        {
            UINT64 UniqueProcessPid;	//PID of the target
            PVOID Source;				//Address in our address spce
            PVOID Destination;			//Addressin in the target address space
            UINT64 Length;				//Size of the copy(in bytes)
            SIZE_T BytesWritten;			//Number of bytes read
        } WriteRequestMessage;

        struct _WriteFromLoaderRequest
        {
            UINT64 LoaderProcessPid;	//PID of the loader
            UINT64 UniqueProcessPid;	//PID of the target
            PVOID Source;				//Address in loader address sapce
            PVOID Destination;			//Address in in the target address space
            UINT64 Length;				//Size of the copy(in bytes)
        } WriteFromLoaderRequestMessage;

        struct _GetModuleBaseAddress
        {
            UINT64 UniqueProcessPid;	//PID of the target
            LPCWSTR ModuleName;			//Module name
            PVOID OutAddress;			//
        } GetModuleBaseAddres;

        struct _AllocRequest
        {
            UINT64 UniqueProcessPid;	//PID of the target
            LPVOID lpAddress;			//Address in the target address space
            SIZE_T dwSize;				//Size of the allocation (in bytes)
            DWORD flAllocationType;		//MEM_ Flags
            DWORD flProtect;			//PAGE_ Flags
        } AllocRequestMessage;

        struct _CreateThreadRequest
        {
            UINT64 UniqueProcessPid;	//PID of the target
            SIZE_T dwStackSize;
            LPVOID lpStartAddress;
            LPVOID lpParameter;
            DWORD  dwCreationFlags;
            LPDWORD lpThreadId;
        } CreateThreadRequestMessage;

        struct _Ping
        {
            UINT64 Response;
        } Ping;
    } Message;
};

signed __int64(*ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter)(char a1, PVOID a2, PVOID a3, PVOID* a4) = nullptr;

void KernelModule::init()
{
    if (ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter != nullptr)
        return;
    auto ntdll = LoadLibrary(TEXT("ntdll.dll"));
    if (ntdll == nullptr)
        return;
    ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter = reinterpret_cast<signed __int64(*)(char a1, PVOID a2, PVOID a3, PVOID * a4)>(GetProcAddress(ntdll, "ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter"));
  /*  auto result = ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(1, &output, &output, nullptr);
    std::cout << "Hello World!" << std::hex << result << "\n";

    std::cout << source << std::endl;
    std::cout << destin << std::endl;

    MyKernelMessage message;
    message.MessageType = MyKernelMessageType::ReadRequest;
    message.Message.ReadRequestMessage.Destination = destin;
    message.Message.ReadRequestMessage.Source = source;
    message.Message.ReadRequestMessage.Length = sizeof(source);
    message.Message.ReadRequestMessage.UniqueProcessPid = GetCurrentProcessId();
    result = ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(69, &message, &message, nullptr);
    std::cout << source << std::endl;
    std::cout << destin << std::endl;

    message.MessageType = MyKernelMessageType::GetModuleBaseAddressRequest;
    message.Message.GetModuleBaseAddres.ModuleName = L"ntdll.dll";
    message.Message.GetModuleBaseAddres.UniqueProcessPid = GetCurrentProcessId();
    message.Message.GetModuleBaseAddres.OutAddress = &output;
    result = ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(69, &message, &message, nullptr);*/
}

BOOL KernelModule::ReadProcessMemory(PVOID pid, PVOID address, PVOID destination, SIZE_T size, SIZE_T* bytesRead)
{
    MyKernelMessage message;
    message.MessageType = MyKernelMessageType::ReadRequest;
    message.Message.ReadRequestMessage.Destination = destination;
    message.Message.ReadRequestMessage.Source = address;
    message.Message.ReadRequestMessage.Length = size;
    message.Message.ReadRequestMessage.UniqueProcessPid = reinterpret_cast<UINT64>(pid);
	message.Message.ReadRequestMessage.BytesRead = 0;
    ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(69, &message, &message, nullptr);
    if (bytesRead != nullptr)
        *bytesRead = message.Message.ReadRequestMessage.BytesRead;
	return NT_SUCCESS(message.RequestStatus);
}

BOOL KernelModule::WriteProcessMemory(UINT64 pid, PVOID address, PVOID source, SIZE_T size, SIZE_T* bytesWritten)
{
	MyKernelMessage message;
	message.MessageType = MyKernelMessageType::WriteRequest;
	message.Message.WriteRequestMessage.BytesWritten = 0;
	message.Message.WriteRequestMessage.UniqueProcessPid = pid;
	message.Message.WriteRequestMessage.Length = size;
	message.Message.WriteRequestMessage.Source = source;
	message.Message.WriteRequestMessage.Destination = address;
	ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(69, &message, &message, nullptr);
	if (bytesWritten != nullptr)
		*bytesWritten = message.Message.WriteRequestMessage.BytesWritten;
	return NT_SUCCESS(message.RequestStatus);
}

BOOL KernelModule::WriteProcessMemoryFromLoader(UINT64 pid, PVOID address, PVOID source, SIZE_T size)
{
    MyKernelMessage message;
    message.MessageType = MyKernelMessageType::WriteFromLoaderRequest;
    message.Message.WriteFromLoaderRequestMessage.LoaderProcessPid = GetCurrentProcessId();
    message.Message.WriteFromLoaderRequestMessage.UniqueProcessPid = pid;
    message.Message.WriteFromLoaderRequestMessage.Length = size;
    message.Message.WriteFromLoaderRequestMessage.Source = source;
    message.Message.WriteFromLoaderRequestMessage.Destination = address;
    ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(69, &message, &message, nullptr);
    return NT_SUCCESS(message.RequestStatus);
}


PVOID KernelModule::GetModuleAddress(UINT64 pid, LPCWSTR moduleName)
{
    MyKernelMessage message;
    message.MessageType = MyKernelMessageType::GetModuleBaseAddressRequest;
    message.Message.GetModuleBaseAddres.ModuleName = moduleName;
    message.Message.GetModuleBaseAddres.UniqueProcessPid = pid;
    message.Message.GetModuleBaseAddres.OutAddress = nullptr;
   ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(69, &message, &message, nullptr);
    if (NT_SUCCESS(message.RequestStatus))
        return  message.Message.GetModuleBaseAddres.OutAddress;
    return nullptr;
}

LPVOID KernelModule::VirtualAlloc(UINT64 UniqueProcessPid, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType,
    DWORD flProtect)
{
    MyKernelMessage message;
    message.MessageType = MyKernelMessageType::AllocRequest;
    message.Message.AllocRequestMessage.UniqueProcessPid = UniqueProcessPid;
    message.Message.AllocRequestMessage.lpAddress = lpAddress;
    message.Message.AllocRequestMessage.dwSize = dwSize;
    message.Message.AllocRequestMessage.flAllocationType = flAllocationType;
    message.Message.AllocRequestMessage.flProtect = flProtect;
    ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(69, &message, &message, nullptr);
    if (NT_SUCCESS(message.RequestStatus))
        return  message.Message.AllocRequestMessage.lpAddress;

    return nullptr;
}

BOOL KernelModule::CreateThread(UINT64 UniqueProcessPid, SIZE_T dwStackSize, LPVOID lpStartAddress,
    LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId)
{
    MyKernelMessage message;
    message.MessageType = MyKernelMessageType::CreateThreadRequest;
    message.Message.CreateThreadRequestMessage.UniqueProcessPid = UniqueProcessPid;
    message.Message.CreateThreadRequestMessage.dwStackSize = dwStackSize;
    message.Message.CreateThreadRequestMessage.lpStartAddress = lpStartAddress;
    message.Message.CreateThreadRequestMessage.lpParameter = lpParameter;
    message.Message.CreateThreadRequestMessage.dwCreationFlags = dwCreationFlags;
    message.Message.CreateThreadRequestMessage.lpThreadId = lpThreadId;
    ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(69, &message, &message, nullptr);
    return NT_SUCCESS(message.RequestStatus);
}

BOOL KernelModule::Ping()
{
    MyKernelMessage message;
    message.MessageType = MyKernelMessageType::PingRequest;
    message.Message.Ping.Response = 0;
    ZwConvertBetweenAuxiliaryCounterAndPerformanceCounter(69, &message, &message, nullptr);
    if (NT_SUCCESS(message.RequestStatus) && message.Message.Ping.Response)
        return 1;
    return 0;
}
