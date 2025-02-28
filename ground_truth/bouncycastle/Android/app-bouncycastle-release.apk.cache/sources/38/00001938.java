package kotlinx.coroutines.sync;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.bouncycastle.tls.CipherSuite;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Mutex.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = CipherSuite.TLS_PSK_WITH_NULL_SHA256)
@DebugMetadata(m162c = "kotlinx.coroutines.sync.MutexKt", m161f = "Mutex.kt", m160i = {0, 0, 0}, m159l = {112}, m158m = "withLock", m157n = {"$this$withLock", "owner", "action"}, m156s = {"L$0", "L$1", "L$2"})
/* loaded from: classes.dex */
public final class MutexKt$withLock$1<T> extends ContinuationImpl {
    Object L$0;
    Object L$1;
    Object L$2;
    int label;
    /* synthetic */ Object result;

    /* JADX INFO: Access modifiers changed from: package-private */
    public MutexKt$withLock$1(Continuation<? super MutexKt$withLock$1> continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        return MutexKt.withLock(null, null, null, this);
    }
}