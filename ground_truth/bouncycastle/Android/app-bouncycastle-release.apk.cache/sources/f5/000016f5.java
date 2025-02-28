package kotlinx.coroutines.channels;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: Deprecated.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = 48)
@DebugMetadata(m162c = "kotlinx.coroutines.channels.ChannelsKt__DeprecatedKt", m161f = "Deprecated.kt", m160i = {0, 0, 0, 1, 1, 1, 1}, m159l = {TypedValues.CycleType.TYPE_EASING, TypedValues.CycleType.TYPE_CUSTOM_WAVE_SHAPE}, m158m = "maxWith", m157n = {"comparator", "$this$consume$iv", "iterator", "comparator", "$this$consume$iv", "iterator", "max"}, m156s = {"L$0", "L$1", "L$2", "L$0", "L$1", "L$2", "L$3"})
/* loaded from: classes.dex */
public final class ChannelsKt__DeprecatedKt$maxWith$1<E> extends ContinuationImpl {
    Object L$0;
    Object L$1;
    Object L$2;
    Object L$3;
    int label;
    /* synthetic */ Object result;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ChannelsKt__DeprecatedKt$maxWith$1(Continuation<? super ChannelsKt__DeprecatedKt$maxWith$1> continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        Object maxWith;
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        maxWith = Deprecated.maxWith(null, null, this);
        return maxWith;
    }
}