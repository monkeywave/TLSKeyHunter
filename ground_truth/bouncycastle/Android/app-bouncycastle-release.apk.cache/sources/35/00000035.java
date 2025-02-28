package androidx.activity;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.bouncycastle.tls.CipherSuite;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: FullyDrawnReporter.kt */
@Metadata(m172k = 3, m171mv = {1, 8, 0}, m169xi = CipherSuite.TLS_PSK_WITH_NULL_SHA256)
@DebugMetadata(m162c = "androidx.activity.FullyDrawnReporterKt", m161f = "FullyDrawnReporter.kt", m160i = {0}, m159l = {CipherSuite.TLS_RSA_PSK_WITH_NULL_SHA384}, m158m = "reportWhenComplete", m157n = {"$this$reportWhenComplete"}, m156s = {"L$0"})
/* loaded from: classes.dex */
public final class FullyDrawnReporterKt$reportWhenComplete$1 extends ContinuationImpl {
    Object L$0;
    int label;
    /* synthetic */ Object result;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FullyDrawnReporterKt$reportWhenComplete$1(Continuation<? super FullyDrawnReporterKt$reportWhenComplete$1> continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        return FullyDrawnReporterKt.reportWhenComplete(null, null, this);
    }
}