// ReSharper disable CppLocalVariableMightNotBeInitialized
typedef enum _KOBJECTS {
    EventNotificationObject = 0,
    EventSynchronizationObject = 1,
    MutantObject = 2,
    ProcessObject = 3,
    QueueObject = 4,
    SemaphoreObject = 5,
    ThreadObject = 6,
    GateObject = 7,
    TimerNotificationObject = 8,
    TimerSynchronizationObject = 9,
    Spare2Object = 10,
    Spare3Object = 11,
    Spare4Object = 12,
    Spare5Object = 13,
    Spare6Object = 14,
    Spare7Object = 15,
    Spare8Object = 16,
    Spare9Object = 17,
    ApcObject = 18,
    DpcObject = 19,
    DeviceQueueObject = 20,
    EventPairObject = 21,
    InterruptObject = 22,
    ProfileObject = 23,
    ThreadedDpcObject = 24,
    MaximumKernelObject = 25
} KOBJECTS;

#define IPI_LEVEL 29
#define SYNCH_LEVEL (IPI_LEVEL-1)

EXPORT ARM_STATUS_REGISTER KeArmStatusRegisterGet() {
    ARM_STATUS_REGISTER Value;
    return Value;
}

KIRQL currentIrql;

EXPORT KIRQL KfRaiseIrql(IN KIRQL NewIrql) {
    return (currentIrql = NewIrql);
}

EXPORT KIRQL KiAcquireDispatcherLock() {
    return KfRaiseIrql(SYNCH_LEVEL);
}

EXPORT LONG KeSetEvent(IN OUT PRKEVENT Event, IN KPRIORITY Increment, IN BOOLEAN Wait) {
    KIRQL OldIrql;
    LONG PreviousState;
    PKTHREAD Thread;

    if ((Event->Header.Type == EventNotificationObject) && (Event->Header.SignalState == 1) && !(Wait)) {
        /* Return the signal state (TRUE/Signalled) */
        return TRUE;
    }

    OldIrql = KiAcquireDispatcherLock();

    /* Save the Previous State */
    PreviousState = Event->Header.SignalState;

    /* Set the Event to Signaled */
    Event->Header.SignalState = 1;

    // TODO: Update KeSetEvent

    /* Return the previous State */
    return PreviousState;
}
