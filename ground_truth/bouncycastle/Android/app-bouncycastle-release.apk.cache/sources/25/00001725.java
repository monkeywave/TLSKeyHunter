package kotlinx.coroutines.channels;

import kotlin.Metadata;
import kotlin.coroutines.Continuation;
import kotlin.coroutines.jvm.internal.ContinuationImpl;
import kotlin.coroutines.jvm.internal.DebugMetadata;
import org.bouncycastle.tls.CipherSuite;

/* JADX INFO: Access modifiers changed from: package-private */
/* compiled from: TickerChannels.kt */
@Metadata(m172k = 3, m171mv = {1, 6, 0}, m169xi = 48)
@DebugMetadata(m162c = "kotlinx.coroutines.channels.TickerChannelsKt", m161f = "TickerChannels.kt", m160i = {0, 0, 1, 1, 2, 2}, m159l = {CipherSuite.TLS_DHE_DSS_WITH_AES_256_CBC_SHA256, 108, 109}, m158m = "fixedDelayTicker", m157n = {"channel", "delayMillis", "channel", "delayMillis", "channel", "delayMillis"}, m156s = {"L$0", "J$0", "L$0", "J$0", "L$0", "J$0"})
/* loaded from: classes.dex */
public final class TickerChannelsKt$fixedDelayTicker$1 extends ContinuationImpl {
    long J$0;
    Object L$0;
    int label;
    /* synthetic */ Object result;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TickerChannelsKt$fixedDelayTicker$1(Continuation<? super TickerChannelsKt$fixedDelayTicker$1> continuation) {
        super(continuation);
    }

    @Override // kotlin.coroutines.jvm.internal.BaseContinuationImpl
    public final Object invokeSuspend(Object obj) {
        Object fixedDelayTicker;
        this.result = obj;
        this.label |= Integer.MIN_VALUE;
        fixedDelayTicker = TickerChannels.fixedDelayTicker(0L, 0L, null, this);
        return fixedDelayTicker;
    }
}