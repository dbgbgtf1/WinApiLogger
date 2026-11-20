#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "../common/protocol.h"
#include "../driver/generated/generated_payload.h"
#include "../reader/generated/generated_names.h"

_Static_assert(
    sizeof(LOGGER_CONTEXT) == WIN_API_LOGGER_CONTEXT_SIZE,
    "context must be exactly 64 bytes");
_Static_assert(
    sizeof(LOGGER_QUEUE_HEADER) == WIN_API_LOGGER_QUEUE_HEADER_SIZE,
    "queue header must be exactly 64 bytes");
_Static_assert(
    sizeof(LOGGER_LOG_RECORD) == WIN_API_LOGGER_LOG_RECORD_SIZE,
    "logger record must be exactly 32 bytes");
_Static_assert(
    sizeof(LOGGER_DRIVER_RECORD) == WIN_API_LOGGER_DRIVER_RECORD_SIZE,
    "driver record must be exactly 72 bytes");
_Static_assert(
    WIN_API_LOGGER_QUEUE_CAPACITY == 8190,
    "queue must contain exactly 8190 slots");
_Static_assert(
    WIN_API_LOGGER_PRIVATE_DATA_SIZE == 262208,
    "private data size mismatch");
_Static_assert(
    WIN_API_LOGGER_QUEUE_DATA_SIZE % WIN_API_LOGGER_LOG_RECORD_SIZE == 0,
    "queue data size must contain complete aligned records");

typedef void (*LOGGER_CALLBACK)(void);

extern void LoggerCallAndCheck(
    LOGGER_CALLBACK Callback,
    uint64_t Results[8]);

static LOGGER_CALLBACK g_Callback;

static DWORD WINAPI
LoggerThread(LPVOID Parameter)
{
    volatile LONG *completed = (volatile LONG *)Parameter;
    int index;

    for (index = 1; index < LOGGER_NAME_ENTRY_COUNT; ++index) {
        if (g_name_entries[index - 1].module_id >
                g_name_entries[index].module_id ||
            (g_name_entries[index - 1].module_id ==
                 g_name_entries[index].module_id &&
             g_name_entries[index - 1].hook_rva >=
                 g_name_entries[index].hook_rva)) {
            fprintf(stderr, "name table is not strictly sorted\n");
            return 1;
        }
    }
    for (index = 0; index < 500; ++index) {
        g_Callback();
    }
    InterlockedIncrement(completed);
    return 0;
}

static void
BytePatch32(BYTE *Address, int32_t Value)
{
    memcpy(Address, &Value, sizeof(Value));
}

static void
BytePatch64(BYTE *Address, uint64_t Value)
{
    memcpy(Address, &Value, sizeof(Value));
}

static BOOL
BuildStub(
    BYTE *StubBase,
    BYTE *Hook,
    BYTE *LoggerEntry,
    BYTE *Context,
    uint64_t ModuleIdRva)
{
    BYTE *Stub = StubBase + 16;
    int32_t displacement;
    intptr_t continuation;

    ZeroMemory(StubBase, 0x100);
    BytePatch64(StubBase + 0, (uint64_t)(uintptr_t)Context);
    BytePatch64(StubBase + 8, (uint64_t)(uintptr_t)LoggerEntry);

    Stub[0] = 0xF3;
    Stub[1] = 0x0F;
    Stub[2] = 0x1E;
    Stub[3] = 0xFA;
    Stub[4] = 0xFF;
    Stub[5] = 0x35;
    displacement = (int32_t)(-((intptr_t)(Stub + 10) -
                               (intptr_t)StubBase));
    BytePatch32(Stub + 6, displacement);
    Stub[10] = 0xFF;
    Stub[11] = 0x35;
    displacement = (int32_t)((Stub + 37) - (Stub + 16));
    BytePatch32(Stub + 12, displacement);
    Stub[16] = 0xFF;
    Stub[17] = 0x15;
    displacement = (int32_t)((StubBase + 8) - (Stub + 22));
    BytePatch32(Stub + 18, displacement);
    Stub[22] = 0x48;
    Stub[23] = 0x8D;
    Stub[24] = 0x64;
    Stub[25] = 0x24;
    Stub[26] = 0x10;
    memset(Stub + 27, 0x90, 5);
    Stub[32] = 0xE9;
    continuation = (intptr_t)(Hook + 5) - (intptr_t)(Stub + 37);
    BytePatch32(Stub + 33, (int32_t)continuation);
    BytePatch64(Stub + 37, ModuleIdRva);
    memset(Stub + 45, 0xCC, 3);

    Hook[0] = 0xE9;
    displacement = (int32_t)(Stub - (Hook + 5));
    BytePatch32(Hook + 1, displacement);
    return TRUE;
}

int
main(void)
{
    SIZE_T code_size = 0x1000;
    BYTE *code = VirtualAlloc(
        NULL,
        code_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    BYTE *private_data = VirtualAlloc(
        NULL,
        WIN_API_LOGGER_PRIVATE_DATA_SIZE,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    LOGGER_CONTEXT *context;
    LOGGER_QUEUE_HEADER *queue;
    LOGGER_LOG_RECORD *record;
    BYTE *fake_hook;
    BYTE *stub_base;
    LOGGER_CALLBACK callback;
    uint64_t raw_head;
    uint64_t preserved[8];
    uint32_t tid = GetCurrentThreadId();
    uint32_t expected_pid = 4242;
    uint32_t expected_rva = 0x10B7D0;
    uint64_t module_id_rva = ((uint64_t)0 << 32) | expected_rva;
    DWORD old_protection;
    int failures = 0;
    int index;

    if (code == NULL || private_data == NULL) {
        fprintf(stderr, "VirtualAlloc failed: %lu\n", GetLastError());
        return 1;
    }
    memcpy(code, g_logger_payload, LOGGER_PAYLOAD_SIZE);
    fake_hook = code + 0x800;
    stub_base = code + 0x900;
    context = (LOGGER_CONTEXT *)private_data;
    queue = (LOGGER_QUEUE_HEADER *)
        (private_data + WIN_API_LOGGER_CONTEXT_SIZE);

    ZeroMemory(context, WIN_API_LOGGER_PRIVATE_DATA_SIZE);
    context->Magic = WIN_API_LOGGER_CONTEXT_MAGIC;
    context->Version = WIN_API_LOGGER_CLIENT_VERSION;
    context->ProcessId = expected_pid;
    context->QueueVa = (uint64_t)(uintptr_t)queue;
    context->QueueSize = WIN_API_LOGGER_QUEUE_DATA_SIZE;
    context->QueueCapacity = WIN_API_LOGGER_QUEUE_CAPACITY;
    queue->Magic = WIN_API_LOGGER_QUEUE_MAGIC;
    queue->Capacity = WIN_API_LOGGER_QUEUE_DATA_SIZE;
    queue->RecordStride = WIN_API_LOGGER_LOG_RECORD_SIZE;

    fake_hook[5] = 0xC3;
    if (!BuildStub(
            stub_base,
            fake_hook,
            code + LOGGER_PAYLOAD_ENTRY_RVA,
            (BYTE *)context,
            module_id_rva)) {
        return 1;
    }

    if (!VirtualProtect(
            code,
            code_size,
            PAGE_EXECUTE_READ,
            &old_protection)) {
        fprintf(stderr, "VirtualProtect failed: %lu\n", GetLastError());
        return 1;
    }
    FlushInstructionCache(GetCurrentProcess(), code, code_size);

    fprintf(stderr, "step: LoggerEntry\n");
    fflush(stderr);
    callback = (LOGGER_CALLBACK)fake_hook;
    LoggerCallAndCheck(callback, preserved);
    for (index = 0; index < 7; ++index) {
        uint64_t expected = 0x1111111111111111ULL *
                            (uint64_t)(index + 1);
        if (preserved[index] != expected) {
            fprintf(
                stderr,
                "register %d not preserved: 0x%llx/0x%llx\n",
                index,
                (unsigned long long)preserved[index],
                (unsigned long long)expected);
            ++failures;
        }
    }
    if ((preserved[7] & 1u) == 0) {
        fprintf(stderr, "flags were not preserved: 0x%llx\n",
                (unsigned long long)preserved[7]);
        ++failures;
    }

    raw_head = queue->Head;
    if (raw_head != ((uint64_t)WIN_API_LOGGER_LOG_RECORD_SIZE << 1)) {
        fprintf(stderr, "queue head mismatch: 0x%llx\n",
                (unsigned long long)raw_head);
        ++failures;
    }

    {
        HANDLE threads[4] = { NULL, NULL, NULL, NULL };
        volatile LONG completed = 0;
        g_Callback = callback;
        for (index = 0; index < 4; ++index) {
            threads[index] = CreateThread(
                NULL,
                0,
                LoggerThread,
                (LPVOID)&completed,
                0,
                NULL);
            if (threads[index] == NULL) {
                fprintf(stderr, "CreateThread failed: %lu\n",
                        GetLastError());
                ++failures;
                break;
            }
        }
        if (index == 4) {
            WaitForMultipleObjects(4, threads, TRUE, INFINITE);
        }
        for (index = 0; index < 4; ++index) {
            if (threads[index] != NULL) {
                CloseHandle(threads[index]);
            }
        }
        if (completed != 4) {
            fprintf(stderr, "not all worker threads completed: %ld\n",
                    completed);
            ++failures;
        }
    }

    raw_head = queue->Head;
    if ((raw_head >> 1) !=
        (uint64_t)(2001 * WIN_API_LOGGER_LOG_RECORD_SIZE)) {
        fprintf(stderr, "concurrent queue head mismatch: 0x%llx\n",
                (unsigned long long)raw_head);
        ++failures;
    }

    while ((queue->Head >> 1) < WIN_API_LOGGER_QUEUE_DATA_SIZE) {
        callback();
    }
    callback();
    if ((queue->Head >> 1) != WIN_API_LOGGER_QUEUE_DATA_SIZE ||
        queue->Dropped != 1) {
        fprintf(
            stderr,
            "full-queue handling mismatch: head=0x%llx dropped=%llu\n",
            (unsigned long long)queue->Head,
            (unsigned long long)queue->Dropped);
        ++failures;
    }

    InterlockedExchange64(
        (volatile LONG64 *)&queue->Tail,
        (LONG64)(WIN_API_LOGGER_QUEUE_DATA_SIZE -
                 2u * WIN_API_LOGGER_LOG_RECORD_SIZE));
    callback();
    callback();
    if ((queue->Head >> 1) !=
        (uint64_t)WIN_API_LOGGER_QUEUE_DATA_SIZE +
            2u * WIN_API_LOGGER_LOG_RECORD_SIZE) {
        fprintf(stderr, "queue wrap failed\n");
        ++failures;
    }

    record = (LOGGER_LOG_RECORD *)
        ((BYTE *)queue + WIN_API_LOGGER_QUEUE_HEADER_SIZE);
    if (record->Length != WIN_API_LOGGER_LOG_RECORD_SIZE ||
        record->Version != WIN_API_LOGGER_CLIENT_VERSION ||
        record->ProcessId != expected_pid ||
        record->ThreadId != tid ||
        record->ModuleId != 0 ||
        record->HookRva != expected_rva ||
        record->Reserved2 != 0 ||
        record->CallerAddress == 0) {
        fprintf(
            stderr,
            "record mismatch: len=%u ver=%u pid=%u tid=%u/%u "
            "module=%u rva=0x%x/0x%x caller=0x%llx\n",
            record->Length,
            record->Version,
            record->ProcessId,
            record->ThreadId,
            tid,
            record->ModuleId,
            record->HookRva,
            expected_rva,
            (unsigned long long)record->CallerAddress);
        ++failures;
    }

    VirtualFree(private_data, 0, MEM_RELEASE);
    VirtualFree(code, 0, MEM_RELEASE);
    if (failures == 0) {
        printf("logger runtime test: PASS\n");
        return 0;
    }
    return 1;
}
