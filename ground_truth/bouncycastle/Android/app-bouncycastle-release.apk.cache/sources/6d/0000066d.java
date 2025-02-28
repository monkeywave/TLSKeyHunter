package androidx.core.p003os;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Functions;
import org.bouncycastle.tls.CipherSuite;

/* compiled from: Handler.kt */
@Metadata(m174d1 = {"\u0000\b\n\u0000\n\u0002\u0010\u0002\n\u0000\u0010\u0000\u001a\u00020\u0001H\n¢\u0006\u0002\b\u0002"}, m173d2 = {"<anonymous>", "", "run"}, m172k = 3, m171mv = {1, 7, 1}, m169xi = CipherSuite.TLS_PSK_WITH_NULL_SHA256)
/* renamed from: androidx.core.os.HandlerKt$postAtTime$runnable$1 */
/* loaded from: classes.dex */
public final class HandlerKt$postAtTime$runnable$1 implements Runnable {
    final /* synthetic */ Functions<Unit> $action;

    public HandlerKt$postAtTime$runnable$1(Functions<Unit> functions) {
        this.$action = functions;
    }

    @Override // java.lang.Runnable
    public final void run() {
        this.$action.invoke();
    }
}