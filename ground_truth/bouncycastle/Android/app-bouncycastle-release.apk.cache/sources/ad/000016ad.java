package kotlinx.coroutines.channels;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.intrinsics.IntrinsicsKt;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: AbstractChannel.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = 48)
@DebugMetadata(m162c = "kotlinx.coroutines.channels.AbstractChannel", m161f = "AbstractChannel.kt", m160i = {}, m159l = {633}, m158m = "receiveCatching-JP2dKIU", m157n = {}, m156s = {})
/* loaded from: classes.dex */
public final class AbstractChannel$receiveCatching$1 extends ContinuationImpl {
    int label;
    /* synthetic */ Object result;
    final /* synthetic */ AbstractChannel<E> this$0;

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    public AbstractChannel$receiveCatching$1(AbstractChannel<E> abstractChannel, Continuation<? super AbstractChannel$receiveCatching$1> continuation) {
        super(continuation);
        this.this$0 = abstractChannel;
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        Object mo1840receiveCatchingJP2dKIU = this.this$0.mo1840receiveCatchingJP2dKIU(this);
        return mo1840receiveCatchingJP2dKIU == IntrinsicsKt.getCOROUTINE_SUSPENDED() ? mo1840receiveCatchingJP2dKIU : ChannelResult.m1847boximpl(mo1840receiveCatchingJP2dKIU);
    }
}