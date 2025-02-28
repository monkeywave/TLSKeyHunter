package androidx.core.p003os;

import android.os.OutcomeReceiver;
import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: OutcomeReceiver.kt */
@Metadata(m174d1 = {"\u0000\u0014\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0002\n\u0002\u0010\u0003\n\u0002\u0018\u0002\n\u0000\u001a.\u0010\u0000\u001a\u000e\u0012\u0004\u0012\u0002H\u0002\u0012\u0004\u0012\u0002H\u00030\u0001\"\u0004\b\u0000\u0010\u0002\"\b\b\u0001\u0010\u0003*\u00020\u0004*\b\u0012\u0004\u0012\u0002H\u00020\u0005H\u0007¨\u0006\u0006"}, m173d2 = {"asOutcomeReceiver", "Landroid/os/OutcomeReceiver;", "R", "E", "", "Lkotlin/coroutines/Continuation;", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.os.OutcomeReceiverKt */
/* loaded from: classes.dex */
public final class OutcomeReceiverKt {
    public static final <R, E extends Throwable> OutcomeReceiver<R, E> asOutcomeReceiver(Continuation<? super R> continuation) {
        Intrinsics.checkNotNullParameter(continuation, "<this>");
        return new OutcomeReceiver(continuation);
    }
}