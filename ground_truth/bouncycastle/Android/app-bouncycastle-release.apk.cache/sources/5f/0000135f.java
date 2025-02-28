package kotlin.concurrent;

import java.util.TimerTask;
import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Function1;
import org.bouncycastle.tls.CipherSuite;

/* compiled from: Timer.kt */
@Metadata(m174d1 = {"\u0000\u0011\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0002\n\u0000*\u0001\u0000\b\n\u0018\u00002\u00020\u0001J\b\u0010\u0002\u001a\u00020\u0003H\u0016¨\u0006\u0004"}, m173d2 = {"kotlin/concurrent/TimersKt$timerTask$1", "Ljava/util/TimerTask;", "run", "", "kotlin-stdlib"}, m172k = 1, m171mv = {1, 8, 0}, m169xi = CipherSuite.TLS_PSK_WITH_NULL_SHA256)
/* loaded from: classes.dex */
public final class TimersKt$timerTask$1 extends TimerTask {
    final /* synthetic */ Function1<TimerTask, Unit> $action;

    /* JADX WARN: Multi-variable type inference failed */
    public TimersKt$timerTask$1(Function1<? super TimerTask, Unit> function1) {
        this.$action = function1;
    }

    @Override // java.util.TimerTask, java.lang.Runnable
    public void run() {
        this.$action.invoke(this);
    }
}