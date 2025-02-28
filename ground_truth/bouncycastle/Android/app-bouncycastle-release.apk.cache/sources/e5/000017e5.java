package kotlinx.coroutines.flow;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.bouncycastle.tls.CipherSuite;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Reduce.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = 48)
@DebugMetadata(m162c = "kotlinx.coroutines.flow.FlowKt__ReduceKt", m161f = "Reduce.kt", m160i = {0, 0, 0}, m159l = {CipherSuite.TLS_RSA_PSK_WITH_AES_256_CBC_SHA384}, m158m = "first", m157n = {"predicate", "result", "collector$iv"}, m156s = {"L$0", "L$1", "L$2"})
/* loaded from: classes.dex */
public final class FlowKt__ReduceKt$first$3<T> extends ContinuationImpl {
    Object L$0;
    Object L$1;
    Object L$2;
    int label;
    /* synthetic */ Object result;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FlowKt__ReduceKt$first$3(Continuation<? super FlowKt__ReduceKt$first$3> continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        return FlowKt.first(null, null, this);
    }
}