package kotlinx.coroutines.flow;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import kotlinx.coroutines.flow.FlowKt__EmittersKt$transform$1;
import org.bouncycastle.tls.CipherSuite;

/* compiled from: Emitters.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = CipherSuite.TLS_PSK_WITH_NULL_SHA256)
@DebugMetadata(m162c = "kotlinx.coroutines.flow.FlowKt__EmittersKt$transform$1$1", m161f = "Emitters.kt", m160i = {}, m159l = {42}, m158m = "emit", m157n = {}, m156s = {})
/* loaded from: classes.dex */
public final class FlowKt__EmittersKt$transform$1$1$emit$1 extends ContinuationImpl {
    int label;
    /* synthetic */ Object result;
    final /* synthetic */ FlowKt__EmittersKt$transform$1.C09591<T> this$0;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public FlowKt__EmittersKt$transform$1$1$emit$1(FlowKt__EmittersKt$transform$1.C09591<? super T> c09591, Continuation<? super FlowKt__EmittersKt$transform$1$1$emit$1> continuation) {
        super(continuation);
        this.this$0 = c09591;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        return this.this$0.emit(null, this);
    }
}