/*
 * RansomDet.c
 * AI-Assisted Ransomware Detection — Windows Kernel Minifilter Driver
 *
 * Batch B31, SIT Tumakuru
 * Track A — Kernel & Systems
 *
 * ── What this driver does ────────────────────────────────────────────────────
 * Registers as a Windows file-system minifilter (WDK model).
 * Intercepts three IRP (I/O Request Packet) major functions:
 *
 *   IRP_MJ_CREATE        → file opened/created
 *   IRP_MJ_WRITE         → file content written
 *   IRP_MJ_SET_INFORMATION → file renamed or deleted
 *
 * For each operation it captures:
 *   - Process ID and name (who is doing this?)
 *   - File path (what file?)
 *   - Operation type and timestamp
 *
 * Events are queued and sent to user mode via a FltCommunicationPort.
 * The Python monitor_service reads them and forwards to the FastAPI backend.
 *
 * ── What this driver does NOT do ─────────────────────────────────────────────
 * It does NOT block, modify, or delay any I/O operation.
 * All callbacks return FLT_PREOP_SUCCESS_WITH_CALLBACK (observe and pass through).
 * This makes it safe: a bug in our code cannot corrupt files.
 * Blocking behaviour is implemented in the user-mode layer after ML inference.
 *
 * ── Build ─────────────────────────────────────────────────────────────────────
 * Open RansomDet.sln in Visual Studio 2022 with WDK installed.
 * Set configuration to Debug x64.
 * Build → the output is driver\x64\Debug\RansomDet.sys
 */

#include <fltKernel.h>
#include <dontuse.h>
#include "RansomDet.h"

/* ── Pragma comments ─────────────────────────────────────────────────────────
 * Tell the linker to include the filter manager import library.
 */
#pragma comment(lib, "fltmgr.lib")

/* Suppress "conditional expression is constant" warnings from WDK macros */
#pragma warning(disable: 4127)

/* ── Filter handle ───────────────────────────────────────────────────────────
 * Returned by FltRegisterFilter; needed for all subsequent Flt* calls.
 */
PFLT_FILTER gFilterHandle = NULL;

/* ── Communication port ──────────────────────────────────────────────────────
 * gServerPort: the kernel-side port this driver created.
 * gClientPort: the connection from the user-mode monitor (one at a time).
 */
PFLT_PORT gServerPort = NULL;
PFLT_PORT gClientPort = NULL;

/* ── Event queue ──────────────────────────────────────────────────────────────
 * We use a simple spin-lock protected queue so pre-operation callbacks
 * (which run at IRQL <= APC_LEVEL) can enqueue events without blocking,
 * and a worker thread dequeues and sends them to user mode.
 *
 * For simplicity in this academic version we send synchronously in the
 * callback itself (FltSendMessage with timeout=0 drops if port busy).
 * A production driver would use a real work queue.
 */
KSPIN_LOCK gQueueLock;


/* ══════════════════════════════════════════════════════════════════════════════
 * HELPER: Get the name of the current process
 * ══════════════════════════════════════════════════════════════════════════════*/
static VOID 
RdGetProcessName( 
    _Out_writes_(MaxChars) PWCHAR Buffer, 
    _In_ ULONG MaxChars 
) 
{ 
    if (Buffer == NULL || MaxChars == 0) { 
        return; 
    } 

    Buffer[0] = L'u';
    Buffer[1] = L'n';
    Buffer[2] = L'k';
    Buffer[3] = L'n';
    Buffer[4] = L'o';
    Buffer[5] = L'w';
    Buffer[6] = L'n';
    Buffer[7] = L'.';
    Buffer[8] = L'e';
    Buffer[9] = L'x';
    Buffer[10] = L'e';
    Buffer[11] = L'\0';
}

/* ══════════════════════════════════════════════════════════════════════════════
 * HELPER: Fill and send one event to user mode
 *
 * Called from each pre-operation callback.
 * FltSendMessage with Timeout=0 is non-blocking: if user mode isn't
 * reading fast enough the event is dropped rather than stalling the I/O.
 * ══════════════════════════════════════════════════════════════════════════════*/
static VOID
RdSendEvent(
    _In_ ULONG        Operation,
    _In_ PUNICODE_STRING FilePath,
    _In_opt_ PUNICODE_STRING NewFilePath,
    _In_ ULONGLONG    FileSize
)
{
    RANSOMDET_EVENT evt = { 0 };
    LARGE_INTEGER   timeout = { 0 };   /* 0 = non-blocking */

    if (!gClientPort) return;          /* no user-mode listener connected */

    /* Fill event fields */
    evt.Operation  = Operation;
    evt.ProcessId  = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    evt.FileSize   = FileSize;

    /* Timestamp as FILETIME (100-nanosecond ticks since Jan 1 1601) */
    LARGE_INTEGER systemTime;
    KeQuerySystemTime(&systemTime);
    evt.Timestamp = systemTime.QuadPart;

    /* Process name */
    RdGetProcessName(evt.ProcessName, RANSOMDET_MAX_PROCNAME);

    /* File path — copy as much as fits */
    if (FilePath && FilePath->Buffer) {
        ULONG copyChars = min(
            (ULONG)(FilePath->Length / sizeof(WCHAR)),
            RANSOMDET_MAX_PATH - 1
        );
        RtlCopyMemory(evt.FilePath, FilePath->Buffer, copyChars * sizeof(WCHAR));
        evt.FilePath[copyChars] = L'\0';
    }

    /* New path (rename destination) */
    if (NewFilePath && NewFilePath->Buffer) {
        ULONG copyChars = min(
            (ULONG)(NewFilePath->Length / sizeof(WCHAR)),
            RANSOMDET_MAX_PATH - 1
        );
        RtlCopyMemory(evt.NewFilePath, NewFilePath->Buffer, copyChars * sizeof(WCHAR));
        evt.NewFilePath[copyChars] = L'\0';
    }

    /* Send to user mode. Reply buffer = NULL (fire and forget). */
    FltSendMessage(
        gFilterHandle,
        &gClientPort,
        &evt,
        sizeof(evt),
        NULL,    /* reply buffer — not used */
        NULL,    /* reply length */
        &timeout /* non-blocking */
    );
}


/* ══════════════════════════════════════════════════════════════════════════════
 * PRE-OPERATION CALLBACK: IRP_MJ_CREATE
 * Fires when any process opens or creates a file.
 * ══════════════════════════════════════════════════════════════════════════════*/
FLT_PREOP_CALLBACK_STATUS
RdPreCreate(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    /* Skip directory operations and paging I/O */
    if (FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DIRECTORY_FILE)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    /* Get file name */
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        RdSendEvent(OP_CREATE, &nameInfo->Name, NULL, 0);
        FltReleaseFileNameInformation(nameInfo);
    }

    UNREFERENCED_PARAMETER(FltObjects);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


/* ══════════════════════════════════════════════════════════════════════════════
 * PRE-OPERATION CALLBACK: IRP_MJ_WRITE
 * Fires BEFORE a write completes — this is the key early-detection hook.
 * We observe the write while it's still in progress, not after.
 * ══════════════════════════════════════════════════════════════════════════════*/
FLT_PREOP_CALLBACK_STATUS
RdPreWrite(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    /* Skip paging I/O (OS virtual memory swapping — not user files) */
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO | IRP_SYNCHRONOUS_PAGING_IO)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    ULONGLONG writeLength = Data->Iopb->Parameters.Write.Length;

    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    if (NT_SUCCESS(status)) {
        FltParseFileNameInformation(nameInfo);
        RdSendEvent(OP_WRITE, &nameInfo->Name, NULL, writeLength);
        FltReleaseFileNameInformation(nameInfo);
    }

    UNREFERENCED_PARAMETER(FltObjects);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


/* ══════════════════════════════════════════════════════════════════════════════
 * PRE-OPERATION CALLBACK: IRP_MJ_SET_INFORMATION
 * Covers both RENAME and DELETE operations.
 * Rename: FileRenameInformation / FileRenameInformationEx
 * Delete: FileDispositionInformation / FileDispositionInformationEx
 * ══════════════════════════════════════════════════════════════════════════════*/
FLT_PREOP_CALLBACK_STATUS
RdPreSetInformation(
    _Inout_ PFLT_CALLBACK_DATA    Data,
    _In_    PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
)
{
    UNREFERENCED_PARAMETER(CompletionContext);
    UNREFERENCED_PARAMETER(FltObjects);

    FILE_INFORMATION_CLASS infoClass =
        Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    /* Get source file name */
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    NTSTATUS status = FltGetFileNameInformation(
        Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT,
        &nameInfo
    );
    if (!NT_SUCCESS(status)) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }
    FltParseFileNameInformation(nameInfo);

    if (infoClass == FileRenameInformation ||
        infoClass == FileRenameInformationEx)
    {
        /* Extract destination path from the rename info buffer */
        PFILE_RENAME_INFORMATION renameInfo =
            (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;

        UNICODE_STRING newName;
        newName.Buffer = renameInfo->FileName;
        newName.Length = (USHORT)renameInfo->FileNameLength;
        newName.MaximumLength = newName.Length;

        RdSendEvent(OP_RENAME, &nameInfo->Name, &newName, 0);
    }
    else if (infoClass == FileDispositionInformation ||
             infoClass == FileDispositionInformationEx)
    {
        RdSendEvent(OP_DELETE, &nameInfo->Name, NULL, 0);
    }

    FltReleaseFileNameInformation(nameInfo);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


/* ══════════════════════════════════════════════════════════════════════════════
 * COMMUNICATION PORT: Connect callback
 * Called when the user-mode monitor connects to our port.
 * We store the client port so RdSendEvent can use it.
 * ══════════════════════════════════════════════════════════════════════════════*/
NTSTATUS
RdPortConnect(
    _In_ PFLT_PORT        ClientPort,
    _In_ PVOID            ServerPortCookie,
    _In_reads_bytes_(SizeOfContext) PVOID ConnectionContext,
    _In_ ULONG            SizeOfContext,
    _Flt_ConnectionCookie_Outptr_ PVOID* ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionCookie);

    gClientPort = ClientPort;
    DbgPrint("[RansomDet] User-mode monitor connected.\n");
    return STATUS_SUCCESS;
}


/* ══════════════════════════════════════════════════════════════════════════════
 * COMMUNICATION PORT: Disconnect callback
 * Called when the user-mode monitor disconnects or crashes.
 * ══════════════════════════════════════════════════════════════════════════════*/
VOID
RdPortDisconnect(
    _In_opt_ PVOID ConnectionCookie
)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gFilterHandle, &gClientPort);
    gClientPort = NULL;
    DbgPrint("[RansomDet] User-mode monitor disconnected.\n");
}


/* ══════════════════════════════════════════════════════════════════════════════
 * FILTER UNLOAD
 * Called when the driver is unloaded (sc stop RansomDet).
 * Must clean up all resources in reverse order of creation.
 * ══════════════════════════════════════════════════════════════════════════════*/
NTSTATUS
RdFilterUnload(
    _In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
    UNREFERENCED_PARAMETER(Flags);

    DbgPrint("[RansomDet] Unloading driver.\n");

    if (gServerPort) {
        FltCloseCommunicationPort(gServerPort);
    }
    if (gFilterHandle) {
        FltUnregisterFilter(gFilterHandle);
    }
    return STATUS_SUCCESS;
}


/* ══════════════════════════════════════════════════════════════════════════════
 * FILTER REGISTRATION TABLE
 * Tells the filter manager which IRP major functions we hook and
 * which callbacks to invoke.
 * ══════════════════════════════════════════════════════════════════════════════*/
static const FLT_OPERATION_REGISTRATION Callbacks[] = {

    {   IRP_MJ_CREATE,
        0,
        RdPreCreate,    /* pre-operation */
        NULL            /* post-operation — not needed */
    },

    {   IRP_MJ_WRITE,
        0,
        RdPreWrite,
        NULL
    },

    {   IRP_MJ_SET_INFORMATION,
        0,
        RdPreSetInformation,
        NULL
    },

    { IRP_MJ_OPERATION_END }  /* sentinel — must be last */
};

static const FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),       /* Size */
    FLT_REGISTRATION_VERSION,       /* Version */
    0,                              /* Flags */
    NULL,                           /* Context registrations */
    Callbacks,                      /* Operation callbacks */
    RdFilterUnload,                 /* Unload callback */
    NULL,                           /* InstanceSetup */
    NULL,                           /* InstanceQueryTeardown */
    NULL,                           /* InstanceTeardownStart */
    NULL,                           /* InstanceTeardownComplete */
    NULL,                           /* GenerateFileName */
    NULL,                           /* NormalizeNameComponent */
    NULL                            /* TransactionNotification */
};


/* ══════════════════════════════════════════════════════════════════════════════
 * DRIVER ENTRY — the main() of a kernel driver
 *
 * Execution order:
 *   1. Register the minifilter with the filter manager
 *   2. Create the communication port (user mode will connect to this)
 *   3. Start filtering (FltStartFiltering)
 *
 * If any step fails we clean up and return the error.
 * Windows will not load the driver if DriverEntry returns an error.
 * ══════════════════════════════════════════════════════════════════════════════*/
NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName = RTL_CONSTANT_STRING(RANSOMDET_PORT_NAME);
    PSECURITY_DESCRIPTOR sd = NULL;

    DbgPrint("[RansomDet] DriverEntry — initializing.\n");

    KeInitializeSpinLock(&gQueueLock);

    /* ── Step 1: Register the minifilter ─────────────────────────────────── */
    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RansomDet] FltRegisterFilter failed: 0x%08X\n", status);
        return status;
    }

    /* ── Step 2: Create communication port ───────────────────────────────── */
    /*
     * The security descriptor controls who can connect.
     * FltBuildDefaultSecurityDescriptor gives access to SYSTEM and admins.
     * In a production driver you'd tighten this to just your service account.
     */
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RansomDet] FltBuildDefaultSecurityDescriptor failed: 0x%08X\n", status);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    InitializeObjectAttributes(
        &oa,
        &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE,
        NULL,
        sd
    );

    status = FltCreateCommunicationPort(
        gFilterHandle,
        &gServerPort,
        &oa,
        NULL,           /* server port cookie */
        RdPortConnect,
        RdPortDisconnect,
        NULL,           /* message notify — not used (we push, not pull) */
        1               /* max connections — one monitor at a time */
    );
    FltFreeSecurityDescriptor(sd);

    if (!NT_SUCCESS(status)) {
        DbgPrint("[RansomDet] FltCreateCommunicationPort failed: 0x%08X\n", status);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    /* ── Step 3: Start filtering ──────────────────────────────────────────── */
    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        DbgPrint("[RansomDet] FltStartFiltering failed: 0x%08X\n", status);
        FltCloseCommunicationPort(gServerPort);
        FltUnregisterFilter(gFilterHandle);
        return status;
    }

    DbgPrint("[RansomDet] Driver loaded. Waiting for user-mode monitor on %ws.\n",
             RANSOMDET_PORT_NAME);
    return STATUS_SUCCESS;
}
