package kotlinx.coroutines.selects;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.bouncycastle.tls.CipherSuite;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: WhileSelect.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = CipherSuite.TLS_PSK_WITH_NULL_SHA256)
@DebugMetadata(m162c = "kotlinx.coroutines.selects.WhileSelectKt", m161f = "WhileSelect.kt", m160i = {0}, m159l = {37}, m158m = "whileSelect", m157n = {"builder"}, m156s = {"L$0"})
/* loaded from: classes.dex */
public final class WhileSelectKt$whileSelect$1 extends ContinuationImpl {
    Object L$0;
    int label;
    /* synthetic */ Object result;

    /* JADX INFO: Access modifiers changed from: package-private */
    public WhileSelectKt$whileSelect$1(Continuation<? super WhileSelectKt$whileSelect$1> continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        return WhileSelect.whileSelect(null, this);
    }
}