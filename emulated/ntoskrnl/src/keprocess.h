#pragma once

#include "types.h"

// Credits @ https://www.vergiliusproject.com/kernels/x86/windows-10
typedef struct _KAFFINITY_EX {
    USHORT Count;                                                           //0x0
    USHORT Size;                                                            //0x2
    ULONG Reserved;                                                         //0x4
    ULONGLONG Bitmap[20];                                                   //0x8
} KAFFINITY_EX;

typedef union _KEXECUTE_OPTIONS {
    UCHAR ExecuteDisable:1;                                                 //0x0
    UCHAR ExecuteEnable:1;                                                  //0x0
    UCHAR DisableThunkEmulation:1;                                          //0x0
    UCHAR Permanent:1;                                                      //0x0
    UCHAR ExecuteDispatchEnable:1;                                          //0x0
    UCHAR ImageDispatchEnable:1;                                            //0x0
    UCHAR DisableExceptionChainValidation:1;                                //0x0
    UCHAR Spare:1;                                                          //0x0
    volatile UCHAR ExecuteOptions;                                          //0x0
    UCHAR ExecuteOptionsNV;                                                 //0x0
} KEXECUTE_OPTIONS;

typedef union _KSTACK_COUNT {
    LONG Value;                                                             //0x0
    ULONG State:3;                                                          //0x0
    ULONG StackCount:29;                                                    //0x0
} KSTACK_COUNT;

typedef struct _DISPATCHER_HEADER {
    union {
        struct {
            UCHAR Type;
            union {
                UCHAR Abandoned;
                UCHAR Absolute;
                UCHAR NpxIrql;
                UCHAR Signalling;
            };
            union {
                UCHAR Size;
                UCHAR Hand;
            };
            union {
                UCHAR Inserted;
                UCHAR DebugActive;
                UCHAR DpcActive;
            };
        };
        LONG Lock;
    };
    LONG SignalState;
    LIST_ENTRY WaitListHead;
} DISPATCHER_HEADER, *PDISPATCHER_HEADER;

typedef struct _PEB_LDR_DATA {
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB {
    UCHAR InheritedAddressSpace;
    UCHAR ReadImageFileExecOptions;
    UCHAR BeingDebugged;
    UCHAR BitField;
    ULONG ImageUsesLargePages: 1;
    ULONG IsProtectedProcess: 1;
    ULONG IsLegacyProcess: 1;
    ULONG IsImageDynamicallyRelocated: 1;
    ULONG SpareBits: 4;
    PVOID Mutant;
    PVOID ImageBaseAddress;
    PPEB_LDR_DATA Ldr;
} PEB, *PPEB;

typedef struct _KPROCESS {
    struct _DISPATCHER_HEADER Header;                                       //0x0
    struct _LIST_ENTRY ProfileListHead;                                     //0x18
    ULONGLONG DirectoryTableBase;                                           //0x28
    struct _LIST_ENTRY ThreadListHead;                                      //0x30
    ULONG ProcessLock;                                                      //0x40
    ULONG ProcessTimerDelay;                                                //0x44
    ULONGLONG DeepFreezeStartTime;                                          //0x48
    struct _KAFFINITY_EX Affinity;                                          //0x50
    ULONGLONG AffinityPadding[12];                                          //0xf8
    struct _LIST_ENTRY ReadyListHead;                                       //0x158
    struct _SINGLE_LIST_ENTRY SwapListEntry;                                //0x168
    volatile struct _KAFFINITY_EX ActiveProcessors;                         //0x170
    ULONGLONG ActiveProcessorsPadding[12];                                  //0x218
    union {
        struct {
            ULONG AutoAlignment:1;                                          //0x278
            ULONG DisableBoost:1;                                           //0x278
            ULONG DisableQuantum:1;                                         //0x278
            ULONG DeepFreeze:1;                                             //0x278
            ULONG TimerVirtualization:1;                                    //0x278
            ULONG CheckStackExtents:1;                                      //0x278
            ULONG CacheIsolationEnabled:1;                                  //0x278
            ULONG PpmPolicy:3;                                              //0x278
            ULONG VaSpaceDeleted:1;                                         //0x278
            ULONG ReservedFlags:21;                                         //0x278
        };
        volatile LONG ProcessFlags;                                         //0x278
    };
    ULONG ActiveGroupsMask;                                                 //0x27c
    CHAR BasePriority;                                                      //0x280
    CHAR QuantumReset;                                                      //0x281
    CHAR Visited;                                                           //0x282
    union _KEXECUTE_OPTIONS Flags;                                          //0x283
    USHORT ThreadSeed[20];                                                  //0x284
    USHORT ThreadSeedPadding[12];                                           //0x2ac
    USHORT IdealProcessor[20];                                              //0x2c4
    USHORT IdealProcessorPadding[12];                                       //0x2ec
    USHORT IdealNode[20];                                                   //0x304
    USHORT IdealNodePadding[12];                                            //0x32c
    USHORT IdealGlobalNode;                                                 //0x344
    USHORT Spare1;                                                          //0x346
    volatile union _KSTACK_COUNT StackCount;                                //0x348
    struct _LIST_ENTRY ProcessListEntry;                                    //0x350
    ULONGLONG CycleTime;                                                    //0x360
    ULONGLONG ContextSwitches;                                              //0x368
    struct _KSCHEDULING_GROUP* SchedulingGroup;                             //0x370
    ULONG FreezeCount;                                                      //0x378
    ULONG KernelTime;                                                       //0x37c
    ULONG UserTime;                                                         //0x380
    ULONG ReadyTime;                                                        //0x384
    ULONGLONG UserDirectoryTableBase;                                       //0x388
    UCHAR AddressPolicy;                                                    //0x390
    UCHAR Spare2[71];                                                       //0x391
    VOID* InstrumentationCallback;                                          //0x3d8
    union {
        ULONGLONG SecureHandle;                                             //0x3e0
        struct {
            ULONGLONG SecureProcess:1;                                      //0x3e0
            ULONGLONG Unused:1;                                             //0x3e0
        } Flags;                                                            //0x3e0
    } SecureState;                                                          //0x3e0
    ULONGLONG KernelWaitTime;                                               //0x3e8
    ULONGLONG UserWaitTime;                                                 //0x3f0
    ULONGLONG EndPadding[8];                                                //0x3f8
} KPROCESS, *PKPROCESS;

typedef struct _EX_PUSH_LOCK {
    union {
        struct {
            ULONGLONG Locked:1;                                             //0x0
            ULONGLONG Waiting:1;                                            //0x0
            ULONGLONG Waking:1;                                             //0x0
            ULONGLONG MultipleShared:1;                                     //0x0
            ULONGLONG Shared:60;                                            //0x0
        };
        ULONGLONG Value;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
} EX_PUSH_LOCK;

struct _EX_FAST_REF {
    union {
        VOID* Object;                                                       //0x0
        ULONGLONG RefCnt:4;                                                 //0x0
        ULONGLONG Value;                                                    //0x0
    };
};

struct _RTL_AVL_TREE {
    struct _RTL_BALANCED_NODE* Root;                                        //0x0
};

struct _SE_AUDIT_PROCESS_CREATION_INFO {
    struct _OBJECT_NAME_INFORMATION* ImageFileName;                         //0x0
};

struct _MMSUPPORT_FLAGS {
    union {
        struct {
            UCHAR WorkingSetType:3;                                         //0x0
            UCHAR Reserved0:3;                                              //0x0
            UCHAR MaximumWorkingSetHard:1;                                  //0x0
            UCHAR MinimumWorkingSetHard:1;                                  //0x0
            UCHAR SessionMaster:1;                                          //0x1
            UCHAR TrimmerState:2;                                           //0x1
            UCHAR Reserved:1;                                               //0x1
            UCHAR PageStealers:4;                                           //0x1
        };
        USHORT u1;                                                          //0x0
    };
    UCHAR MemoryPriority;                                                   //0x2
    union {
        struct {
            UCHAR WsleDeleted:1;                                            //0x3
            UCHAR SvmEnabled:1;                                             //0x3
            UCHAR ForceAge:1;                                               //0x3
            UCHAR ForceTrim:1;                                              //0x3
            UCHAR NewMaximum:1;                                             //0x3
            UCHAR CommitReleaseState:2;                                     //0x3
        };
        UCHAR u2;                                                           //0x3
    };
};

struct _MMSUPPORT_INSTANCE {
    ULONG NextPageColor;                                                    //0x0
    ULONG PageFaultCount;                                                   //0x4
    ULONGLONG TrimmedPageCount;                                             //0x8
    struct _MMWSL_INSTANCE* VmWorkingSetList;                               //0x10
    struct _LIST_ENTRY WorkingSetExpansionLinks;                            //0x18
    ULONGLONG AgeDistribution[8];                                           //0x28
    struct _KGATE* ExitOutswapGate;                                         //0x68
    ULONGLONG MinimumWorkingSetSize;                                        //0x70
    ULONGLONG WorkingSetLeafSize;                                           //0x78
    ULONGLONG WorkingSetLeafPrivateSize;                                    //0x80
    ULONGLONG WorkingSetSize;                                               //0x88
    ULONGLONG WorkingSetPrivateSize;                                        //0x90
    ULONGLONG MaximumWorkingSetSize;                                        //0x98
    ULONGLONG PeakWorkingSetSize;                                           //0xa0
    ULONG HardFaultCount;                                                   //0xa8
    USHORT LastTrimStamp;                                                   //0xac
    USHORT PartitionId;                                                     //0xae
    ULONGLONG SelfmapLock;                                                  //0xb0
    struct _MMSUPPORT_FLAGS Flags;                                          //0xb8
};

struct _MMSUPPORT_SHARED {
    volatile LONG WorkingSetLock;                                           //0x0
    LONG GoodCitizenWaiting;                                                //0x4
    ULONGLONG ReleasedCommitDebt;                                           //0x8
    ULONGLONG ResetPagesRepurposedCount;                                    //0x10
    VOID* WsSwapSupport;                                                    //0x18
    VOID* CommitReleaseContext;                                             //0x20
    VOID* AccessLog;                                                        //0x28
    volatile ULONGLONG ChargedWslePages;                                    //0x30
    ULONGLONG ActualWslePages;                                              //0x38
    ULONGLONG WorkingSetCoreLock;                                           //0x40
    VOID* ShadowMapping;                                                    //0x48
};

struct _MMSUPPORT_FULL {
    struct _MMSUPPORT_INSTANCE Instance;                                    //0x0
    struct _MMSUPPORT_SHARED Shared;                                        //0xc0
};

struct _ALPC_PROCESS_CONTEXT {
    struct _EX_PUSH_LOCK Lock;                                              //0x0
    struct _LIST_ENTRY ViewListHead;                                        //0x8
    volatile ULONGLONG PagedPoolQuotaCache;                                 //0x18
};

struct _PS_PROTECTION {
    union {
        UCHAR Level;                                                        //0x0
        struct {
            UCHAR Type:3;                                                   //0x0
            UCHAR Audit:1;                                                  //0x0
            UCHAR Signer:4;                                                 //0x0
        };
    };
};

union _PS_INTERLOCKED_TIMER_DELAY_VALUES {
    ULONGLONG DelayMs:30;                                                   //0x0
    ULONGLONG CoalescingWindowMs:30;                                        //0x0
    ULONGLONG Reserved:1;                                                   //0x0
    ULONGLONG NewTimerWheel:1;                                              //0x0
    ULONGLONG Retry:1;                                                      //0x0
    ULONGLONG Locked:1;                                                     //0x0
    ULONGLONG All;                                                          //0x0
};

struct _JOBOBJECT_WAKE_FILTER {
    ULONG HighEdgeFilter;                                                   //0x0
    ULONG LowEdgeFilter;                                                    //0x4
};

struct _PS_PROCESS_WAKE_INFORMATION {
    ULONGLONG NotificationChannel;                                          //0x0
    ULONG WakeCounters[7];                                                  //0x8
    struct _JOBOBJECT_WAKE_FILTER WakeFilter;                               //0x24
    ULONG NoWakeCounter;                                                    //0x2c
};

struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES {
    struct _RTL_AVL_TREE Tree;                                              //0x0
    struct _EX_PUSH_LOCK Lock;                                              //0x8
};

typedef struct _EX_RUNDOWN_REF {
    union {
        ULONGLONG Count;                                                    //0x0
        VOID* Ptr;                                                          //0x0
    };
} EX_RUNDOWN_REF, *PEX_RUNDOWN_REF;

struct _WNF_STATE_NAME {
    ULONG Data[2];                                                          //0x0
};

struct _EWOW64PROCESS {
    VOID* Peb;                                                              //0x0
    enum _SYSTEM_DLL_TYPE NtdllType;                                        //0x8
};

typedef enum _PS_QUOTA_TYPE {
    PsNonPagedPool = 0,
    PsPagedPool,
    PsPageFile,
#if (NTDDI_VERSION >= NTDDI_LONGHORN)
    PsWorkingSet,
#endif
#if (NTDDI_VERSION == NTDDI_LONGHORN)
    PsCpuRate,
#endif
    PsQuotaTypes
} PS_QUOTA_TYPE;

typedef struct _EPROCESS {
    struct _KPROCESS Pcb;                                                   //0x0
    struct _EX_PUSH_LOCK ProcessLock;                                       //0x438
    VOID* UniqueProcessId;                                                  //0x440
    struct _LIST_ENTRY ActiveProcessLinks;                                  //0x448
    struct _EX_RUNDOWN_REF RundownProtect;                                  //0x458
    union {
        ULONG Flags2;                                                       //0x460
        struct {
            ULONG JobNotReallyActive:1;                                     //0x460
            ULONG AccountingFolded:1;                                       //0x460
            ULONG NewProcessReported:1;                                     //0x460
            ULONG ExitProcessReported:1;                                    //0x460
            ULONG ReportCommitChanges:1;                                    //0x460
            ULONG LastReportMemory:1;                                       //0x460
            ULONG ForceWakeCharge:1;                                        //0x460
            ULONG CrossSessionCreate:1;                                     //0x460
            ULONG NeedsHandleRundown:1;                                     //0x460
            ULONG RefTraceEnabled:1;                                        //0x460
            ULONG PicoCreated:1;                                            //0x460
            ULONG EmptyJobEvaluated:1;                                      //0x460
            ULONG DefaultPagePriority:3;                                    //0x460
            ULONG PrimaryTokenFrozen:1;                                     //0x460
            ULONG ProcessVerifierTarget:1;                                  //0x460
            ULONG RestrictSetThreadContext:1;                               //0x460
            ULONG AffinityPermanent:1;                                      //0x460
            ULONG AffinityUpdateEnable:1;                                   //0x460
            ULONG PropagateNode:1;                                          //0x460
            ULONG ExplicitAffinity:1;                                       //0x460
            ULONG ProcessExecutionState:2;                                  //0x460
            ULONG EnableReadVmLogging:1;                                    //0x460
            ULONG EnableWriteVmLogging:1;                                   //0x460
            ULONG FatalAccessTerminationRequested:1;                        //0x460
            ULONG DisableSystemAllowedCpuSet:1;                             //0x460
            ULONG ProcessStateChangeRequest:2;                              //0x460
            ULONG ProcessStateChangeInProgress:1;                           //0x460
            ULONG InPrivate:1;                                              //0x460
        };
    };
    union {
        ULONG Flags;                                                        //0x464
        struct {
            ULONG CreateReported:1;                                         //0x464
            ULONG NoDebugInherit:1;                                         //0x464
            ULONG ProcessExiting:1;                                         //0x464
            ULONG ProcessDelete:1;                                          //0x464
            ULONG ManageExecutableMemoryWrites:1;                           //0x464
            ULONG VmDeleted:1;                                              //0x464
            ULONG OutswapEnabled:1;                                         //0x464
            ULONG Outswapped:1;                                             //0x464
            ULONG FailFastOnCommitFail:1;                                   //0x464
            ULONG Wow64VaSpace4Gb:1;                                        //0x464
            ULONG AddressSpaceInitialized:2;                                //0x464
            ULONG SetTimerResolution:1;                                     //0x464
            ULONG BreakOnTermination:1;                                     //0x464
            ULONG DeprioritizeViews:1;                                      //0x464
            ULONG WriteWatch:1;                                             //0x464
            ULONG ProcessInSession:1;                                       //0x464
            ULONG OverrideAddressSpace:1;                                   //0x464
            ULONG HasAddressSpace:1;                                        //0x464
            ULONG LaunchPrefetched:1;                                       //0x464
            ULONG Background:1;                                             //0x464
            ULONG VmTopDown:1;                                              //0x464
            ULONG ImageNotifyDone:1;                                        //0x464
            ULONG PdeUpdateNeeded:1;                                        //0x464
            ULONG VdmAllowed:1;                                             //0x464
            ULONG ProcessRundown:1;                                         //0x464
            ULONG ProcessInserted:1;                                        //0x464
            ULONG DefaultIoPriority:3;                                      //0x464
            ULONG ProcessSelfDelete:1;                                      //0x464
            ULONG SetTimerResolutionLink:1;                                 //0x464
        };
    };
    union _LARGE_INTEGER CreateTime;                                        //0x468
    ULONGLONG ProcessQuotaUsage[2];                                         //0x470
    ULONGLONG ProcessQuotaPeak[2];                                          //0x480
    ULONGLONG PeakVirtualSize;                                              //0x490
    ULONGLONG VirtualSize;                                                  //0x498
    struct _LIST_ENTRY SessionProcessLinks;                                 //0x4a0
    union {
        VOID* ExceptionPortData;                                            //0x4b0
        ULONGLONG ExceptionPortValue;                                       //0x4b0
        ULONGLONG ExceptionPortState:3;                                     //0x4b0
    };
    struct _EX_FAST_REF Token;                                              //0x4b8
    ULONGLONG MmReserved;                                                   //0x4c0
    struct _EX_PUSH_LOCK AddressCreationLock;                               //0x4c8
    struct _EX_PUSH_LOCK PageTableCommitmentLock;                           //0x4d0
    struct _ETHREAD* RotateInProgress;                                      //0x4d8
    struct _ETHREAD* ForkInProgress;                                        //0x4e0
    struct _EJOB* volatile CommitChargeJob;                                 //0x4e8
    struct _RTL_AVL_TREE CloneRoot;                                         //0x4f0
    volatile ULONGLONG NumberOfPrivatePages;                                //0x4f8
    volatile ULONGLONG NumberOfLockedPages;                                 //0x500
    VOID* Win32Process;                                                     //0x508
    struct _EJOB* volatile Job;                                             //0x510
    VOID* SectionObject;                                                    //0x518
    VOID* SectionBaseAddress;                                               //0x520
    ULONG Cookie;                                                           //0x528
    struct _PAGEFAULT_HISTORY* WorkingSetWatch;                             //0x530
    VOID* Win32WindowStation;                                               //0x538
    VOID* InheritedFromUniqueProcessId;                                     //0x540
    volatile ULONGLONG OwnerProcessId;                                      //0x548
    struct _PEB* Peb;                                                       //0x550
    struct _MM_SESSION_SPACE* Session;                                      //0x558
    VOID* Spare1;                                                           //0x560
    struct _EPROCESS_QUOTA_BLOCK* QuotaBlock;                               //0x568
    struct _HANDLE_TABLE* ObjectTable;                                      //0x570
    VOID* DebugPort;                                                        //0x578
    struct _EWOW64PROCESS* WoW64Process;                                    //0x580
    VOID* DeviceMap;                                                        //0x588
    VOID* EtwDataSource;                                                    //0x590
    ULONGLONG PageDirectoryPte;                                             //0x598
    struct _FILE_OBJECT* ImageFilePointer;                                  //0x5a0
    UCHAR ImageFileName[15];                                                //0x5a8
    UCHAR PriorityClass;                                                    //0x5b7
    VOID* SecurityPort;                                                     //0x5b8
    struct _SE_AUDIT_PROCESS_CREATION_INFO SeAuditProcessCreationInfo;      //0x5c0
    struct _LIST_ENTRY JobLinks;                                            //0x5c8
    VOID* HighestUserAddress;                                               //0x5d8
    struct _LIST_ENTRY ThreadListHead;                                      //0x5e0
    volatile ULONG ActiveThreads;                                           //0x5f0
    ULONG ImagePathHash;                                                    //0x5f4
    ULONG DefaultHardErrorProcessing;                                       //0x5f8
    LONG LastThreadExitStatus;                                              //0x5fc
    struct _EX_FAST_REF PrefetchTrace;                                      //0x600
    VOID* LockedPagesList;                                                  //0x608
    union _LARGE_INTEGER ReadOperationCount;                                //0x610
    union _LARGE_INTEGER WriteOperationCount;                               //0x618
    union _LARGE_INTEGER OtherOperationCount;                               //0x620
    union _LARGE_INTEGER ReadTransferCount;                                 //0x628
    union _LARGE_INTEGER WriteTransferCount;                                //0x630
    union _LARGE_INTEGER OtherTransferCount;                                //0x638
    ULONGLONG CommitChargeLimit;                                            //0x640
    volatile ULONGLONG CommitCharge;                                        //0x648
    volatile ULONGLONG CommitChargePeak;                                    //0x650
    struct _MMSUPPORT_FULL Vm;                                              //0x680
    struct _LIST_ENTRY MmProcessLinks;                                      //0x7c0
    ULONG ModifiedPageCount;                                                //0x7d0
    LONG ExitStatus;                                                        //0x7d4
    struct _RTL_AVL_TREE VadRoot;                                           //0x7d8
    VOID* VadHint;                                                          //0x7e0
    ULONGLONG VadCount;                                                     //0x7e8
    volatile ULONGLONG VadPhysicalPages;                                    //0x7f0
    ULONGLONG VadPhysicalPagesLimit;                                        //0x7f8
    struct _ALPC_PROCESS_CONTEXT AlpcContext;                               //0x800
    struct _LIST_ENTRY TimerResolutionLink;                                 //0x820
    struct _PO_DIAG_STACK_RECORD* TimerResolutionStackRecord;               //0x830
    ULONG RequestedTimerResolution;                                         //0x838
    ULONG SmallestTimerResolution;                                          //0x83c
    union _LARGE_INTEGER ExitTime;                                          //0x840
    struct _INVERTED_FUNCTION_TABLE* InvertedFunctionTable;                 //0x848
    struct _EX_PUSH_LOCK InvertedFunctionTableLock;                         //0x850
    ULONG ActiveThreadsHighWatermark;                                       //0x858
    ULONG LargePrivateVadCount;                                             //0x85c
    struct _EX_PUSH_LOCK ThreadListLock;                                    //0x860
    VOID* WnfContext;                                                       //0x868
    struct _EJOB* ServerSilo;                                               //0x870
    UCHAR SignatureLevel;                                                   //0x878
    UCHAR SectionSignatureLevel;                                            //0x879
    struct _PS_PROTECTION Protection;                                       //0x87a
    UCHAR HangCount:3;                                                      //0x87b
    UCHAR GhostCount:3;                                                     //0x87b
    UCHAR PrefilterException:1;                                             //0x87b
    union {
        ULONG Flags3;                                                       //0x87c
        struct {
            ULONG Minimal:1;                                                //0x87c
            ULONG ReplacingPageRoot:1;                                      //0x87c
            ULONG Crashed:1;                                                //0x87c
            ULONG JobVadsAreTracked:1;                                      //0x87c
            ULONG VadTrackingDisabled:1;                                    //0x87c
            ULONG AuxiliaryProcess:1;                                       //0x87c
            ULONG SubsystemProcess:1;                                       //0x87c
            ULONG IndirectCpuSets:1;                                        //0x87c
            ULONG RelinquishedCommit:1;                                     //0x87c
            ULONG HighGraphicsPriority:1;                                   //0x87c
            ULONG CommitFailLogged:1;                                       //0x87c
            ULONG ReserveFailLogged:1;                                      //0x87c
            ULONG SystemProcess:1;                                          //0x87c
            ULONG HideImageBaseAddresses:1;                                 //0x87c
            ULONG AddressPolicyFrozen:1;                                    //0x87c
            ULONG ProcessFirstResume:1;                                     //0x87c
            ULONG ForegroundExternal:1;                                     //0x87c
            ULONG ForegroundSystem:1;                                       //0x87c
            ULONG HighMemoryPriority:1;                                     //0x87c
            ULONG EnableProcessSuspendResumeLogging:1;                      //0x87c
            ULONG EnableThreadSuspendResumeLogging:1;                       //0x87c
            ULONG SecurityDomainChanged:1;                                  //0x87c
            ULONG SecurityFreezeComplete:1;                                 //0x87c
            ULONG VmProcessorHost:1;                                        //0x87c
            ULONG VmProcessorHostTransition:1;                              //0x87c
            ULONG AltSyscall:1;                                             //0x87c
            ULONG TimerResolutionIgnore:1;                                  //0x87c
            ULONG DisallowUserTerminate:1;                                  //0x87c
        };
    };
    LONG DeviceAsid;                                                        //0x880
    VOID* SvmData;                                                          //0x888
    struct _EX_PUSH_LOCK SvmProcessLock;                                    //0x890
    ULONGLONG SvmLock;                                                      //0x898
    struct _LIST_ENTRY SvmProcessDeviceListHead;                            //0x8a0
    ULONGLONG LastFreezeInterruptTime;                                      //0x8b0
    struct _PROCESS_DISK_COUNTERS* DiskCounters;                            //0x8b8
    VOID* PicoContext;                                                      //0x8c0
    VOID* EnclaveTable;                                                     //0x8c8
    ULONGLONG EnclaveNumber;                                                //0x8d0
    struct _EX_PUSH_LOCK EnclaveLock;                                       //0x8d8
    ULONG HighPriorityFaultsAllowed;                                        //0x8e0
    struct _PO_PROCESS_ENERGY_CONTEXT* EnergyContext;                       //0x8e8
    VOID* VmContext;                                                        //0x8f0
    ULONGLONG SequenceNumber;                                               //0x8f8
    ULONGLONG CreateInterruptTime;                                          //0x900
    ULONGLONG CreateUnbiasedInterruptTime;                                  //0x908
    ULONGLONG TotalUnbiasedFrozenTime;                                      //0x910
    ULONGLONG LastAppStateUpdateTime;                                       //0x918
    ULONGLONG LastAppStateUptime:61;                                        //0x920
    ULONGLONG LastAppState:3;                                               //0x920
    volatile ULONGLONG SharedCommitCharge;                                  //0x928
    struct _EX_PUSH_LOCK SharedCommitLock;                                  //0x930
    struct _LIST_ENTRY SharedCommitLinks;                                   //0x938
    union {
        struct {
            ULONGLONG AllowedCpuSets;                                       //0x948
            ULONGLONG DefaultCpuSets;                                       //0x950
        };
        struct {
            ULONGLONG* AllowedCpuSetsIndirect;                              //0x948
            ULONGLONG* DefaultCpuSetsIndirect;                              //0x950
        };
    };
    VOID* DiskIoAttribution;                                                //0x958
    VOID* DxgProcess;                                                       //0x960
    ULONG Win32KFilterSet;                                                  //0x968
    volatile union _PS_INTERLOCKED_TIMER_DELAY_VALUES ProcessTimerDelay;    //0x970
    volatile ULONG KTimerSets;                                              //0x978
    volatile ULONG KTimer2Sets;                                             //0x97c
    volatile ULONG ThreadTimerSets;                                         //0x980
    ULONGLONG VirtualTimerListLock;                                         //0x988
    struct _LIST_ENTRY VirtualTimerListHead;                                //0x990
    union {
        struct _WNF_STATE_NAME WakeChannel;                                 //0x9a0
        struct _PS_PROCESS_WAKE_INFORMATION WakeInfo;                       //0x9a0
    };
    union {
        ULONG MitigationFlags;                                              //0x9d0
        struct {
            ULONG ControlFlowGuardEnabled:1;                                //0x9d0
            ULONG ControlFlowGuardExportSuppressionEnabled:1;               //0x9d0
            ULONG ControlFlowGuardStrict:1;                                 //0x9d0
            ULONG DisallowStrippedImages:1;                                 //0x9d0
            ULONG ForceRelocateImages:1;                                    //0x9d0
            ULONG HighEntropyASLREnabled:1;                                 //0x9d0
            ULONG StackRandomizationDisabled:1;                             //0x9d0
            ULONG ExtensionPointDisable:1;                                  //0x9d0
            ULONG DisableDynamicCode:1;                                     //0x9d0
            ULONG DisableDynamicCodeAllowOptOut:1;                          //0x9d0
            ULONG DisableDynamicCodeAllowRemoteDowngrade:1;                 //0x9d0
            ULONG AuditDisableDynamicCode:1;                                //0x9d0
            ULONG DisallowWin32kSystemCalls:1;                              //0x9d0
            ULONG AuditDisallowWin32kSystemCalls:1;                         //0x9d0
            ULONG EnableFilteredWin32kAPIs:1;                               //0x9d0
            ULONG AuditFilteredWin32kAPIs:1;                                //0x9d0
            ULONG DisableNonSystemFonts:1;                                  //0x9d0
            ULONG AuditNonSystemFontLoading:1;                              //0x9d0
            ULONG PreferSystem32Images:1;                                   //0x9d0
            ULONG ProhibitRemoteImageMap:1;                                 //0x9d0
            ULONG AuditProhibitRemoteImageMap:1;                            //0x9d0
            ULONG ProhibitLowILImageMap:1;                                  //0x9d0
            ULONG AuditProhibitLowILImageMap:1;                             //0x9d0
            ULONG SignatureMitigationOptIn:1;                               //0x9d0
            ULONG AuditBlockNonMicrosoftBinaries:1;                         //0x9d0
            ULONG AuditBlockNonMicrosoftBinariesAllowStore:1;               //0x9d0
            ULONG LoaderIntegrityContinuityEnabled:1;                       //0x9d0
            ULONG AuditLoaderIntegrityContinuity:1;                         //0x9d0
            ULONG EnableModuleTamperingProtection:1;                        //0x9d0
            ULONG EnableModuleTamperingProtectionNoInherit:1;               //0x9d0
            ULONG RestrictIndirectBranchPrediction:1;                       //0x9d0
            ULONG IsolateSecurityDomain:1;                                  //0x9d0
        } MitigationFlagsValues;                                            //0x9d0
    };
    union
    {
        ULONG MitigationFlags2;                                             //0x9d4
        struct
        {
            ULONG EnableExportAddressFilter:1;                              //0x9d4
            ULONG AuditExportAddressFilter:1;                               //0x9d4
            ULONG EnableExportAddressFilterPlus:1;                          //0x9d4
            ULONG AuditExportAddressFilterPlus:1;                           //0x9d4
            ULONG EnableRopStackPivot:1;                                    //0x9d4
            ULONG AuditRopStackPivot:1;                                     //0x9d4
            ULONG EnableRopCallerCheck:1;                                   //0x9d4
            ULONG AuditRopCallerCheck:1;                                    //0x9d4
            ULONG EnableRopSimExec:1;                                       //0x9d4
            ULONG AuditRopSimExec:1;                                        //0x9d4
            ULONG EnableImportAddressFilter:1;                              //0x9d4
            ULONG AuditImportAddressFilter:1;                               //0x9d4
            ULONG DisablePageCombine:1;                                     //0x9d4
            ULONG SpeculativeStoreBypassDisable:1;                          //0x9d4
            ULONG CetUserShadowStacks:1;                                    //0x9d4
            ULONG AuditCetUserShadowStacks:1;                               //0x9d4
            ULONG AuditCetUserShadowStacksLogged:1;                         //0x9d4
            ULONG UserCetSetContextIpValidation:1;                          //0x9d4
            ULONG AuditUserCetSetContextIpValidation:1;                     //0x9d4
            ULONG AuditUserCetSetContextIpValidationLogged:1;               //0x9d4
            ULONG CetUserShadowStacksStrictMode:1;                          //0x9d4
            ULONG BlockNonCetBinaries:1;                                    //0x9d4
            ULONG BlockNonCetBinariesNonEhcont:1;                           //0x9d4
            ULONG AuditBlockNonCetBinaries:1;                               //0x9d4
            ULONG AuditBlockNonCetBinariesLogged:1;                         //0x9d4
            ULONG Reserved1:1;                                              //0x9d4
            ULONG Reserved2:1;                                              //0x9d4
            ULONG Reserved3:1;                                              //0x9d4
            ULONG Reserved4:1;                                              //0x9d4
            ULONG Reserved5:1;                                              //0x9d4
            ULONG CetDynamicApisOutOfProcOnly:1;                            //0x9d4
            ULONG UserCetSetContextIpValidationRelaxedMode:1;               //0x9d4
        } MitigationFlags2Values;                                           //0x9d4
    };
    VOID* PartitionObject;                                                  //0x9d8
    ULONGLONG SecurityDomain;                                               //0x9e0
    ULONGLONG ParentSecurityDomain;                                         //0x9e8
    VOID* CoverageSamplerContext;                                           //0x9f0
    VOID* MmHotPatchContext;                                                //0x9f8
    struct _RTL_AVL_TREE DynamicEHContinuationTargetsTree;                  //0xa00
    struct _EX_PUSH_LOCK DynamicEHContinuationTargetsLock;                  //0xa08
    struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges; //0xa10
    ULONG DisabledComponentFlags;                                           //0xa20
} EPROCESS, *PEPROCESS;

typedef enum _MODE {
    KernelMode,
    UserMode,
    MaximumMode
} MODE;

typedef struct _KAPC_STATE {
    LIST_ENTRY ApcListHead[MaximumMode];
    struct _KPROCESS* Process;
    union {
        UCHAR InProgressFlags;
        struct {
            BOOLEAN KernelApcInProgress : 1;
            BOOLEAN SpecialApcInProgress : 1;
        };
    };

    BOOLEAN KernelApcPending;
    union {
        BOOLEAN UserApcPendingAll;
        struct {
            BOOLEAN SpecialUserApcPending : 1;
            BOOLEAN UserApcPending : 1;
        };
    };
} KAPC_STATE, *PKAPC_STATE, *PRKAPC_STATE;

typedef struct _KWAIT_BLOCK {
    LIST_ENTRY WaitListEntry;
    PVOID Thread; // PKTHREAD
    PVOID Object;
    PVOID NextWaitBlock; // PKWAIT_BLOCK
    WORD WaitKey;
    UCHAR WaitType;
    UCHAR SpareByte;
} KWAIT_BLOCK, *PKWAIT_BLOCK;

typedef struct _KGATE {
    DISPATCHER_HEADER Header;
} KGATE, *PKGATE;

typedef struct _KQUEUE {
    DISPATCHER_HEADER Header;
    LIST_ENTRY EntryListHead;
    ULONG CurrentCount;
    ULONG MaximumCount;
    LIST_ENTRY ThreadListHead;
} KQUEUE, *PKQUEUE;

typedef struct _KDPC {
    UCHAR Type;
    UCHAR Importance;
    WORD Number;
    LIST_ENTRY DpcListEntry;
    PVOID DeferredRoutine;
    PVOID DeferredContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    PVOID DpcData;
} KDPC, *PKDPC;

typedef struct _KTIMER {
    DISPATCHER_HEADER Header;
    ULARGE_INTEGER DueTime;
    LIST_ENTRY TimerListEntry;
    PKDPC Dpc;
    LONG Period;
} KTIMER, *PKTIMER;

typedef struct _KTRAP_FRAME {
    ULONG DbgEbp;
    ULONG DbgEip;
    ULONG DbgArgMark;
    ULONG DbgArgPointer;
    WORD TempSegCs;
    UCHAR Logging;
    UCHAR Reserved;
    ULONG TempEsp;
    ULONG Dr0;
    ULONG Dr1;
    ULONG Dr2;
    ULONG Dr3;
    ULONG Dr6;
    ULONG Dr7;
    ULONG SegGs;
    ULONG SegEs;
    ULONG SegDs;
    ULONG Edx;
    ULONG Ecx;
    ULONG Eax;
    ULONG PreviousPreviousMode;
    PEXCEPTION_REGISTRATION_RECORD ExceptionList;
    ULONG SegFs;
    ULONG Edi;
    ULONG Esi;
    ULONG Ebx;
    ULONG Ebp;
    ULONG ErrCode;
    ULONG Eip;
    ULONG SegCs;
    ULONG EFlags;
    ULONG HardwareEsp;
    ULONG HardwareSegSs;
    ULONG V86Es;
    ULONG V86Ds;
    ULONG V86Fs;
    ULONG V86Gs;
} KTRAP_FRAME, *PKTRAP_FRAME;

typedef struct _KAPC {
    UCHAR Type;
    UCHAR SpareByte0;
    UCHAR Size;
    UCHAR SpareByte1;
    ULONG SpareLong0;
    PVOID Thread; // PKTHREAD
    LIST_ENTRY ApcListEntry;
    PVOID KernelRoutine;
    PVOID RundownRoutine;
    PVOID NormalRoutine;
    PVOID NormalContext;
    PVOID SystemArgument1;
    PVOID SystemArgument2;
    CHAR ApcStateIndex;
    CHAR ApcMode;
    UCHAR Inserted;
} KAPC, *PKAPC;

typedef struct _DESCRIPTOR {
    WORD Pad;
    WORD Limit;
    ULONG Base;
} DESCRIPTOR, *PDESCRIPTOR;

typedef struct _KSPECIAL_REGISTERS {
     ULONG Cr0;
     ULONG Cr2;
     ULONG Cr3;
     ULONG Cr4;
     ULONG KernelDr0;
     ULONG KernelDr1;
     ULONG KernelDr2;
     ULONG KernelDr3;
     ULONG KernelDr6;
     ULONG KernelDr7;
     DESCRIPTOR Gdtr;
     DESCRIPTOR Idtr;
     WORD Tr;
     WORD Ldtr;
     ULONG Reserved[6];
} KSPECIAL_REGISTERS, *PKSPECIAL_REGISTERS;

typedef struct _KPROCESSOR_STATE {
    CONTEXT ContextFrame;
    KSPECIAL_REGISTERS SpecialRegisters;
} KPROCESSOR_STATE, *PKPROCESSOR_STATE;

typedef struct _KSPIN_LOCK_QUEUE {
    struct _KSPIN_LOCK_QUEUE* Next;
    ULONG* Lock;
} KSPIN_LOCK_QUEUE, *PKSPIN_LOCK_QUEUE;

typedef ULONG64 POOL_FLAGS;

#define DEFAULT_TAG 0x656E6F4E // From IDA

typedef PVOID PCPOOL_EXTENDED_PARAMETER;

#define POOL_FLAG_REQUIRED_START          0x0000000000000001UI64
#define POOL_FLAG_USE_QUOTA               0x0000000000000001UI64     // Charge quota
#define POOL_FLAG_UNINITIALIZED           0x0000000000000002UI64     // Don't zero-initialize allocation
#define POOL_FLAG_SESSION                 0x0000000000000004UI64     // Use session specific pool
#define POOL_FLAG_CACHE_ALIGNED           0x0000000000000008UI64     // Cache aligned allocation
#define POOL_FLAG_RESERVED1               0x0000000000000010UI64     // Reserved for system use
#define POOL_FLAG_RAISE_ON_FAILURE        0x0000000000000020UI64     // Raise exception on failure
#define POOL_FLAG_NON_PAGED               0x0000000000000040UI64     // Non paged pool NX
#define POOL_FLAG_NON_PAGED_EXECUTE       0x0000000000000080UI64     // Non paged pool executable
#define POOL_FLAG_PAGED                   0x0000000000000100UI64     // Paged pool
#define POOL_FLAG_RESERVED2               0x0000000000000200UI64     // Reserved for system use
#define POOL_FLAG_RESERVED3               0x0000000000000400UI64     // Reserved for system use
#define POOL_FLAG_REQUIRED_END            0x0000000080000000UI64
#define POOL_FLAG_OPTIONAL_START          0x0000000100000000UI64
#define POOL_FLAG_SPECIAL_POOL            0x0000000100000000UI64     // Make special pool allocation
#define POOL_FLAG_OPTIONAL_END            0x8000000000000000UI64

typedef enum _POOL_TYPE {
    NonPagedPool,
    NonPagedPoolExecute = NonPagedPool,
    PagedPool,
    NonPagedPoolMustSucceed = NonPagedPool + 2,
    DontUseThisType,
    NonPagedPoolCacheAligned = NonPagedPool + 4,
    PagedPoolCacheAligned,
    NonPagedPoolCacheAlignedMustS = NonPagedPool + 6,
    MaxPoolType,
    NonPagedPoolBase = 0,
    NonPagedPoolBaseMustSucceed = NonPagedPoolBase + 2,
    NonPagedPoolBaseCacheAligned = NonPagedPoolBase + 4,
    NonPagedPoolBaseCacheAlignedMustS = NonPagedPoolBase + 6,
    NonPagedPoolSession = 32,
    PagedPoolSession = NonPagedPoolSession + 1,
    NonPagedPoolMustSucceedSession = PagedPoolSession + 1,
    DontUseThisTypeSession = NonPagedPoolMustSucceedSession + 1,
    NonPagedPoolCacheAlignedSession = DontUseThisTypeSession + 1,
    PagedPoolCacheAlignedSession = NonPagedPoolCacheAlignedSession + 1,
    NonPagedPoolCacheAlignedMustSSession = PagedPoolCacheAlignedSession + 1,
    NonPagedPoolNx = 512,
    NonPagedPoolNxCacheAligned = NonPagedPoolNx + 4,
    NonPagedPoolSessionNx = NonPagedPoolNx + 32,
} POOL_TYPE;

typedef struct _GENERAL_LOOKASIDE
{
    union
    {
        SLIST_HEADER ListHead;
        SINGLE_LIST_ENTRY SingleListHead;
    };
    WORD Depth;
    WORD MaximumDepth;
    ULONG TotalAllocates;
    union
    {
        ULONG AllocateMisses;
        ULONG AllocateHits;
    };
    ULONG TotalFrees;
    union
    {
        ULONG FreeMisses;
        ULONG FreeHits;
    };
    POOL_TYPE Type;
    ULONG Tag;
    ULONG Size;
    union
    {
        PVOID * AllocateEx;
        PVOID * Allocate;
    };
    union
    {
        PVOID FreeEx;
        PVOID Free;
    };
    LIST_ENTRY ListEntry;
    ULONG LastTotalAllocates;
    union
    {
        ULONG LastAllocateMisses;
        ULONG LastAllocateHits;
    };
    ULONG Future[2];
} GENERAL_LOOKASIDE, *PGENERAL_LOOKASIDE;

typedef struct _KNODE {
    USHORT NodeNumber;                                                      //0x0
    USHORT PrimaryNodeNumber;                                               //0x2
    ULONG ProximityId;                                                      //0x4
    USHORT MaximumProcessors;                                               //0x8
    struct {
        UCHAR ProcessorOnly:1;                                              //0xa
        UCHAR GroupsAssigned:1;                                             //0xa
        UCHAR MeasurableDistance:1;                                         //0xa
    } Flags;                                                                //0xa
    UCHAR GroupSeed;                                                        //0xb
    UCHAR PrimaryGroup;                                                     //0xc
    UCHAR Padding[3];                                                       //0xd
    ULONG ActiveGroups;                                                     //0x10
    struct _KSCHEDULER_SUBNODE* SchedulerSubNodes[32];                      //0x18
    ULONG ActiveTopologyElements[5];                                        //0x118
} KNODE, *PKNODE;

typedef struct _PP_LOOKASIDE_LIST {
    PGENERAL_LOOKASIDE P;
    PGENERAL_LOOKASIDE L;
} PP_LOOKASIDE_LIST, *PPP_LOOKASIDE_LIST;

typedef struct _GENERAL_LOOKASIDE_POOL
{
    union
    {
        SLIST_HEADER ListHead;
        SINGLE_LIST_ENTRY SingleListHead;
    };
    WORD Depth;
    WORD MaximumDepth;
    ULONG TotalAllocates;
    union
    {
        ULONG AllocateMisses;
        ULONG AllocateHits;
    };
    ULONG TotalFrees;
    union
    {
        ULONG FreeMisses;
        ULONG FreeHits;
    };
    POOL_TYPE Type;
    ULONG Tag;
    ULONG Size;
    union
    {
        PVOID * AllocateEx;
        PVOID * Allocate;
    };
    union
    {
        PVOID FreeEx;
        PVOID Free;
    };
    LIST_ENTRY ListEntry;
    ULONG LastTotalAllocates;
    union
    {
        ULONG LastAllocateMisses;
        ULONG LastAllocateHits;
    };
    ULONG Future[2];
} GENERAL_LOOKASIDE_POOL, *PGENERAL_LOOKASIDE_POOL;

typedef struct _KDPC_DATA {
    LIST_ENTRY DpcListHead;
    ULONG DpcLock;
    LONG DpcQueueDepth;
    ULONG DpcCount;
} KDPC_DATA, *PKDPC_DATA;

typedef struct _KEVENT {
    DISPATCHER_HEADER Header;
} KEVENT, *PKEVENT, *PRKEVENT;

typedef struct _FX_SAVE_AREA {
    BYTE U[520];
    ULONG NpxSavedCpu;
    ULONG Cr0NpxState;
} FX_SAVE_AREA, *PFX_SAVE_AREA;

typedef struct
{
    LONG * IdleHandler;
    ULONG Context;
    ULONG Latency;
    ULONG Power;
    ULONG TimeCheck;
    ULONG StateFlags;
    UCHAR PromotePercent;
    UCHAR DemotePercent;
    UCHAR PromotePercentBase;
    UCHAR DemotePercentBase;
    UCHAR StateType;
} PPM_IDLE_STATE, *PPPM_IDLE_STATE;

typedef struct
{
    ULONG Type;
    ULONG Count;
    ULONG Flags;
    ULONG TargetState;
    ULONG ActualState;
    ULONG OldState;
    ULONG TargetProcessors;
    PPM_IDLE_STATE State[1];
} PPM_IDLE_STATES, *PPPM_IDLE_STATES;

typedef struct
{
     UINT64 StartTime;
     UINT64 EndTime;
     ULONG Reserved[4];
} PROCESSOR_IDLE_TIMES, *PPROCESSOR_IDLE_TIMES;

typedef struct
{
    ULONG Frequency;
    ULONG Power;
    UCHAR PercentFrequency;
    UCHAR IncreaseLevel;
    UCHAR DecreaseLevel;
    UCHAR Type;
    UINT64 Control;
    UINT64 Status;
    ULONG TotalHitCount;
    ULONG DesiredCount;
} PPM_PERF_STATE, *PPPM_PERF_STATE;

typedef struct
{
    ULONG Count;
    ULONG MaxFrequency;
    ULONG MaxPerfState;
    ULONG MinPerfState;
    ULONG LowestPState;
    ULONG IncreaseTime;
    ULONG DecreaseTime;
    UCHAR BusyAdjThreshold;
    UCHAR Reserved;
    UCHAR ThrottleStatesOnly;
    UCHAR PolicyType;
    ULONG TimerInterval;
    ULONG Flags;
    ULONG TargetProcessors;
    LONG * PStateHandler;
    ULONG PStateContext;
    LONG * TStateHandler;
    ULONG TStateContext;
    ULONG* FeedbackHandler;
    PPM_PERF_STATE State[1];
} PPM_PERF_STATES, *PPPM_PERF_STATES;

typedef struct _PROCESSOR_POWER_STATE
{
    PVOID IdleFunction;
    PPPM_IDLE_STATES IdleStates;
    UINT64 LastTimeCheck;
    UINT64 LastIdleTime;
    PROCESSOR_IDLE_TIMES IdleTimes;
    PPPM_IDLE_ACCOUNTING IdleAccounting;
    PPPM_PERF_STATES PerfStates;
    ULONG LastKernelUserTime;
    ULONG LastIdleThreadKTime;
    UINT64 LastGlobalTimeHv;
    UINT64 LastProcessorTimeHv;
    UCHAR ThermalConstraint;
    UCHAR LastBusyPercentage;
    BYTE Flags[6];
    KTIMER PerfTimer;
    KDPC PerfDpc;
    ULONG LastSysTime;
    PVOID PStateMaster; // PKPRCB
    ULONG PStateSet;
    ULONG CurrentPState;
    ULONG Reserved0;
    ULONG DesiredPState;
    ULONG Reserved1;
    ULONG PStateIdleStartTime;
    ULONG PStateIdleTime;
    ULONG LastPStateIdleTime;
    ULONG PStateStartTime;
    ULONG WmiDispatchPtr;
    LONG WmiInterfaceEnabled;
} PROCESSOR_POWER_STATE, *PPROCESSOR_POWER_STATE;

typedef struct _KPRCB {
     WORD MinorVersion;
     WORD MajorVersion;
     PVOID CurrentThread; // PKTHREAD
     PVOID NextThread; // PKTHREAD
     PVOID IdleThread; // PKTHREAD
     UCHAR Number;
     UCHAR NestingLevel;
     WORD BuildType;
     ULONG SetMember;
     CHAR CpuType;
     CHAR CpuID;
     union {
          WORD CpuStep;
          struct {
               UCHAR CpuStepping;
               UCHAR CpuModel;
          };
     };
     KPROCESSOR_STATE ProcessorState;
     ULONG KernelReserved[16];
     ULONG HalReserved[16];
     ULONG CFlushSize;
     UCHAR PrcbPad0[88];
     KSPIN_LOCK_QUEUE LockQueue[33];
     PVOID NpxThread; // PKTHREAD
     ULONG InterruptCount;
     ULONG KernelTime;
     ULONG UserTime;
     ULONG DpcTime;
     ULONG DpcTimeCount;
     ULONG InterruptTime;
     ULONG AdjustDpcThreshold;
     ULONG PageColor;
     UCHAR SkipTick;
     UCHAR DebuggerSavedIRQL;
     UCHAR NodeColor;
     UCHAR PollSlot;
     ULONG NodeShiftedColor;
     PKNODE ParentNode;
     ULONG MultiThreadProcessorSet;
     PVOID MultiThreadSetMaster; // PKPRCB
     ULONG SecondaryColorMask;
     ULONG DpcTimeLimit;
     ULONG CcFastReadNoWait;
     ULONG CcFastReadWait;
     ULONG CcFastReadNotPossible;
     ULONG CcCopyReadNoWait;
     ULONG CcCopyReadWait;
     ULONG CcCopyReadNoWaitMiss;
     LONG MmSpinLockOrdering;
     LONG IoReadOperationCount;
     LONG IoWriteOperationCount;
     LONG IoOtherOperationCount;
     LARGE_INTEGER IoReadTransferCount;
     LARGE_INTEGER IoWriteTransferCount;
     LARGE_INTEGER IoOtherTransferCount;
     ULONG CcFastMdlReadNoWait;
     ULONG CcFastMdlReadWait;
     ULONG CcFastMdlReadNotPossible;
     ULONG CcMapDataNoWait;
     ULONG CcMapDataWait;
     ULONG CcPinMappedDataCount;
     ULONG CcPinReadNoWait;
     ULONG CcPinReadWait;
     ULONG CcMdlReadNoWait;
     ULONG CcMdlReadWait;
     ULONG CcLazyWriteHotSpots;
     ULONG CcLazyWriteIos;
     ULONG CcLazyWritePages;
     ULONG CcDataFlushes;
     ULONG CcDataPages;
     ULONG CcLostDelayedWrites;
     ULONG CcFastReadResourceMiss;
     ULONG CcCopyReadWaitMiss;
     ULONG CcFastMdlReadResourceMiss;
     ULONG CcMapDataNoWaitMiss;
     ULONG CcMapDataWaitMiss;
     ULONG CcPinReadNoWaitMiss;
     ULONG CcPinReadWaitMiss;
     ULONG CcMdlReadNoWaitMiss;
     ULONG CcMdlReadWaitMiss;
     ULONG CcReadAheadIos;
     ULONG KeAlignmentFixupCount;
     ULONG KeExceptionDispatchCount;
     ULONG KeSystemCalls;
     ULONG PrcbPad1[3];
     PP_LOOKASIDE_LIST PPLookasideList[16];
     GENERAL_LOOKASIDE_POOL PPNPagedLookasideList[32];
     GENERAL_LOOKASIDE_POOL PPPagedLookasideList[32];
     ULONG PacketBarrier;
     LONG ReverseStall;
     PVOID IpiFrame;
     UCHAR PrcbPad2[52];
     VOID * CurrentPacket[3];
     ULONG TargetSet;
     PVOID WorkerRoutine;
     ULONG IpiFrozen;
     UCHAR PrcbPad3[40];
     ULONG RequestSummary;
     PVOID SignalDone; // PKPRCB
     UCHAR PrcbPad4[56];
     KDPC_DATA DpcData[2];
     PVOID DpcStack;
     LONG MaximumDpcQueueDepth;
     ULONG DpcRequestRate;
     ULONG MinimumDpcRate;
     UCHAR DpcInterruptRequested;
     UCHAR DpcThreadRequested;
     UCHAR DpcRoutineActive;
     UCHAR DpcThreadActive;
     ULONG PrcbLock;
     ULONG DpcLastCount;
     ULONG TimerHand;
     ULONG TimerRequest;
     PVOID PrcbPad41;
     KEVENT DpcEvent;
     UCHAR ThreadDpcEnable;
     UCHAR QuantumEnd;
     UCHAR PrcbPad50;
     UCHAR IdleSchedule;
     LONG DpcSetEventRequest;
     LONG Sleeping;
     ULONG PeriodicCount;
     ULONG PeriodicBias;
     UCHAR PrcbPad5[6];
     LONG TickOffset;
     KDPC CallDpc;
     LONG ClockKeepAlive;
     UCHAR ClockCheckSlot;
     UCHAR ClockPollCycle;
     UCHAR PrcbPad6[2];
     LONG DpcWatchdogPeriod;
     LONG DpcWatchdogCount;
     LONG ThreadWatchdogPeriod;
     LONG ThreadWatchdogCount;
     ULONG PrcbPad70[2];
     LIST_ENTRY WaitListHead;
     ULONG WaitLock;
     ULONG ReadySummary;
     ULONG QueueIndex;
     SINGLE_LIST_ENTRY DeferredReadyListHead;
     UINT64 StartCycles;
     UINT64 CycleTime;
     UINT64 PrcbPad71[3];
     LIST_ENTRY DispatcherReadyListHead[32];
     PVOID ChainedInterruptList;
     LONG LookasideIrpFloat;
     LONG MmPageFaultCount;
     LONG MmCopyOnWriteCount;
     LONG MmTransitionCount;
     LONG MmCacheTransitionCount;
     LONG MmDemandZeroCount;
     LONG MmPageReadCount;
     LONG MmPageReadIoCount;
     LONG MmCacheReadCount;
     LONG MmCacheIoCount;
     LONG MmDirtyPagesWriteCount;
     LONG MmDirtyWriteIoCount;
     LONG MmMappedPagesWriteCount;
     LONG MmMappedWriteIoCount;
     ULONG CachedCommit;
     ULONG CachedResidentAvailable;
     PVOID HyperPte;
     UCHAR CpuVendor;
     UCHAR PrcbPad9[3];
     UCHAR VendorString[13];
     UCHAR InitialApicId;
     UCHAR CoresPerPhysicalProcessor;
     UCHAR LogicalProcessorsPerPhysicalProcessor;
     ULONG MHz;
     ULONG FeatureBits;
     LARGE_INTEGER UpdateSignature;
     UINT64 IsrTime;
     UINT64 SpareField1;
     FX_SAVE_AREA NpxSaveArea;
     PROCESSOR_POWER_STATE PowerState;
     KDPC DpcWatchdogDpc;
     KTIMER DpcWatchdogTimer;
     PVOID WheaInfo;
     PVOID EtwSupport;
     SLIST_HEADER InterruptObjectPool;
     LARGE_INTEGER HypercallPagePhysical;
     PVOID HypercallPageVirtual;
     PVOID RateControl;
     CACHE_DESCRIPTOR Cache[5];
     ULONG CacheCount;
     ULONG CacheProcessorMask[5];
     UCHAR LogicalProcessorsPerCore;
     UCHAR PrcbPad8[3];
     ULONG PackageProcessorSet;
     ULONG CoreProcessorSet;
} KPRCB, *PKPRCB;

typedef struct _KSEMAPHORE {
    DISPATCHER_HEADER Header;
    LONG Limit;
} KSEMAPHORE, *PKSEMAPHORE;

typedef struct _KTHREAD {
     DISPATCHER_HEADER Header;
     UINT64 CycleTime;
     ULONG HighCycleTime;
     UINT64 QuantumTarget;
     PVOID InitialStack;
     PVOID StackLimit;
     PVOID KernelStack;
     ULONG ThreadLock;
     union {
          KAPC_STATE ApcState;
          UCHAR ApcStateFill[23];
     };
     CHAR Priority;
     WORD NextProcessor;
     WORD DeferredProcessor;
     ULONG ApcQueueLock;
     ULONG ContextSwitches;
     UCHAR State;
     UCHAR NpxState;
     UCHAR WaitIrql;
     CHAR WaitMode;
     LONG WaitStatus;
     union {
          PKWAIT_BLOCK WaitBlockList;
          PKGATE GateObject;
     };
     union {
          ULONG KernelStackResident: 1;
          ULONG ReadyTransition: 1;
          ULONG ProcessReadyQueue: 1;
          ULONG WaitNext: 1;
          ULONG SystemAffinityActive: 1;
          ULONG Alertable: 1;
          ULONG GdiFlushActive: 1;
          ULONG Reserved: 25;
          LONG MiscFlags;
     };
     UCHAR WaitReason;
     UCHAR SwapBusy;
     UCHAR Alerted[2];
     union {
          LIST_ENTRY WaitListEntry;
          SINGLE_LIST_ENTRY SwapListEntry;
     };
     PKQUEUE Queue;
     ULONG WaitTime;
     union {
          struct {
               SHORT KernelApcDisable;
               SHORT SpecialApcDisable;
          };
          ULONG CombinedApcDisable;
     };
     PVOID Teb;
     union {
          KTIMER Timer;
          UCHAR TimerFill[40];
     };
     union {
          ULONG AutoAlignment: 1;
          ULONG DisableBoost: 1;
          ULONG EtwStackTraceApc1Inserted: 1;
          ULONG EtwStackTraceApc2Inserted: 1;
          ULONG CycleChargePending: 1;
          ULONG CalloutActive: 1;
          ULONG ApcQueueable: 1;
          ULONG EnableStackSwap: 1;
          ULONG GuiThread: 1;
          ULONG ReservedFlags: 23;
          LONG ThreadFlags;
     };
     union {
          KWAIT_BLOCK WaitBlock[4];
          struct {
               UCHAR WaitBlockFill0[23];
               UCHAR IdealProcessor;
          };
          struct {
               UCHAR WaitBlockFill1[47];
               CHAR PreviousMode;
          };
          struct {
               UCHAR WaitBlockFill2[71];
               UCHAR ResourceIndex;
          };
          UCHAR WaitBlockFill3[95];
     };
     UCHAR LargeStack;
     LIST_ENTRY QueueListEntry;
     PKTRAP_FRAME TrapFrame;
     PVOID FirstArgument;
     union {
          PVOID CallbackStack;
          ULONG CallbackDepth;
     };
     PVOID ServiceTable;
     UCHAR ApcStateIndex;
     CHAR BasePriority;
     CHAR PriorityDecrement;
     UCHAR Preempted;
     UCHAR AdjustReason;
     CHAR AdjustIncrement;
     UCHAR Spare01;
     CHAR Saturation;
     ULONG SystemCallNumber;
     ULONG Spare02;
     ULONG UserAffinity;
     PKPROCESS Process;
     ULONG Affinity;
     PKAPC_STATE ApcStatePointer[2];
     union {
          KAPC_STATE SavedApcState;
          UCHAR SavedApcStateFill[23];
     };
     CHAR FreezeCount;
     CHAR SuspendCount;
     UCHAR UserIdealProcessor;
     UCHAR Spare03;
     UCHAR Iopl;
     PVOID Win32Thread;
     PVOID StackBase;
     union {
          KAPC SuspendApc;
          struct {
               UCHAR SuspendApcFill0[1];
               CHAR Spare04;
          };
          struct {
               UCHAR SuspendApcFill1[3];
               UCHAR QuantumReset;
          };
          struct {
               UCHAR SuspendApcFill2[4];
               ULONG KernelTime;
          };
          struct {
               UCHAR SuspendApcFill3[36];
               PKPRCB WaitPrcb;
          };
          struct {
               UCHAR SuspendApcFill4[40];
               PVOID LegoData;
          };
          UCHAR SuspendApcFill5[47];
     };
     UCHAR PowerState;
     ULONG UserTime;
     union {
          KSEMAPHORE SuspendSemaphore;
          UCHAR SuspendSemaphorefill[20];
     };
     ULONG SListFaultCount;
     LIST_ENTRY ThreadListEntry;
     LIST_ENTRY MutantListHead;
     PVOID SListFaultAddress;
     PVOID MdlForLockedTeb;
} KTHREAD, *PKTHREAD;

typedef struct _KIPCR
{
    union
    {
        NT_TIB NtTib;
        struct
        {
            union _KGDTENTRY64 *GdtBase;
            struct _KTSS64 *TssBase;
            ULONG64 UserRsp;
            struct _KPCR *Self;
            struct _KPRCB *CurrentPrcb;
            PKSPIN_LOCK_QUEUE LockArray;
            PVOID Used_Self;
        };
    };
    union _KIDTENTRY64 *IdtBase;
    ULONG64 Unused[2];
    KIRQL Irql;
    UCHAR SecondLevelCacheAssociativity;
    UCHAR ObsoleteNumber;
    UCHAR Fill0;
    ULONG Unused0[3];
    USHORT MajorVersion;
    USHORT MinorVersion;
    ULONG StallScaleFactor;
    PVOID Unused1[3];
    ULONG KernelReserved[15];
    ULONG SecondLevelCacheSize;
    ULONG HalReserved[16];
    ULONG Unused2;
    ULONG Fill1;
    PVOID KdVersionBlock; // 0x108
    PVOID Unused3;
    ULONG PcrAlign1[24];
    ULONG Fill2[2]; // 0x178
    KPRCB Prcb; // 0x180
    ULONG ContextSwitches;
} KIPCR, *PKIPCR;
