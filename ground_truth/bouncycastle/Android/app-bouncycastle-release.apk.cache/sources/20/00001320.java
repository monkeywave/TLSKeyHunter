package kotlin.collections;

import kotlin.Metadata;

/* compiled from: AbstractIterator.kt */
@Metadata(m174d1 = {"\u0000\f\n\u0002\u0018\u0002\n\u0002\u0010\u0010\n\u0002\b\u0006\b\u0082\u0001\u0018\u00002\b\u0012\u0004\u0012\u00020\u00000\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002j\u0002\b\u0003j\u0002\b\u0004j\u0002\b\u0005j\u0002\b\u0006¨\u0006\u0007"}, m173d2 = {"Lkotlin/collections/State;", "", "(Ljava/lang/String;I)V", "Ready", "NotReady", "Done", "Failed", "kotlin-stdlib"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = 48)
/* loaded from: classes.dex */
enum State {
    Ready,
    NotReady,
    Done,
    Failed
}