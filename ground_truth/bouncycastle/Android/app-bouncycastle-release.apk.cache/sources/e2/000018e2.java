package kotlinx.coroutines.internal;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.DebugProbes;

@Metadata(m174d1 = {"\u0000\n\n\u0000\n\u0002\u0018\u0002\n\u0002\b\u0003\u001a#\u0010\u0000\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001\"\u0004\b\u0000\u0010\u00022\f\u0010\u0003\u001a\b\u0012\u0004\u0012\u0002H\u00020\u0001H\u0080\b¨\u0006\u0004"}, m173d2 = {"probeCoroutineCreated", "Lkotlin/coroutines/Continuation;", "T", "completion", "kotlinx-coroutines-core"}, m172k = 2, m171mv = {1, 6, 0}, m169xi = 48)
/* renamed from: kotlinx.coroutines.internal.ProbesSupportKt */
/* loaded from: classes.dex */
public final class ProbesSupport {
    public static final <T> Continuation<T> probeCoroutineCreated(Continuation<? super T> continuation) {
        return DebugProbes.probeCoroutineCreated(continuation);
    }
}