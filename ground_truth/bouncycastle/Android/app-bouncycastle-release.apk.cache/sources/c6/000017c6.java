package kotlinx.coroutines.flow;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Limit.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = 48)
@DebugMetadata(m162c = "kotlinx.coroutines.flow.FlowKt__LimitKt", m161f = "Limit.kt", m160i = {0}, m159l = {73}, m158m = "emitAbort$FlowKt__LimitKt", m157n = {"$this$emitAbort"}, m156s = {"L$0"})
/* loaded from: classes.dex */
public final class FlowKt__LimitKt$emitAbort$1<T> extends ContinuationImpl {
    Object L$0;
    int label;
    /* synthetic */ Object result;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FlowKt__LimitKt$emitAbort$1(Continuation<? super FlowKt__LimitKt$emitAbort$1> continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        Object emitAbort$FlowKt__LimitKt;
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        emitAbort$FlowKt__LimitKt = Limit.emitAbort$FlowKt__LimitKt(null, null, this);
        return emitAbort$FlowKt__LimitKt;
    }
}