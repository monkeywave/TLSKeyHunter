package kotlinx.coroutines.channels;

import java.util.Collection;
import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Deprecated.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = 48)
@DebugMetadata(m162c = "kotlinx.coroutines.channels.ChannelsKt__DeprecatedKt", m161f = "Deprecated.kt", m160i = {0, 0}, m159l = {487}, m158m = "toCollection", m157n = {"destination", "$this$consume$iv$iv"}, m156s = {"L$0", "L$1"})
/* loaded from: classes.dex */
public final class ChannelsKt__DeprecatedKt$toCollection$1<E, C extends Collection<? super E>> extends ContinuationImpl {
    Object L$0;
    Object L$1;
    Object L$2;
    int label;
    /* synthetic */ Object result;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ChannelsKt__DeprecatedKt$toCollection$1(Continuation<? super ChannelsKt__DeprecatedKt$toCollection$1> continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        return ChannelsKt.toCollection(null, null, this);
    }
}