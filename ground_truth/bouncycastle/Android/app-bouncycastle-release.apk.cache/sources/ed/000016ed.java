package kotlinx.coroutines.channels;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.bouncycastle.asn1.eac.EACTags;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Deprecated.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = 48)
@DebugMetadata(m162c = "kotlinx.coroutines.channels.ChannelsKt__DeprecatedKt", m161f = "Deprecated.kt", m160i = {0, 0}, m159l = {EACTags.DEPRECATED}, m158m = "firstOrNull", m157n = {"$this$consume$iv", "iterator"}, m156s = {"L$0", "L$1"})
/* loaded from: classes.dex */
public final class ChannelsKt__DeprecatedKt$firstOrNull$1<E> extends ContinuationImpl {
    Object L$0;
    Object L$1;
    int label;
    /* synthetic */ Object result;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ChannelsKt__DeprecatedKt$firstOrNull$1(Continuation<? super ChannelsKt__DeprecatedKt$firstOrNull$1> continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        Object firstOrNull;
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        firstOrNull = Deprecated.firstOrNull(null, this);
        return firstOrNull;
    }
}