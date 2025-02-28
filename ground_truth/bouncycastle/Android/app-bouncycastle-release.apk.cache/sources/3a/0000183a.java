package kotlinx.coroutines.flow;

import kotlin.Metadata;
import kotlin.jvm.functions.Functions;
import kotlin.jvm.internal.Intrinsics;
import kotlin.jvm.internal.Lambda;
import org.bouncycastle.tls.CipherSuite;

/* JADX INFO: Add missing generic type declarations: [T] */
/* compiled from: Zip.kt */
@Metadata(m174d1 = {"\u0000\n\n\u0000\n\u0002\u0010\u0011\n\u0002\b\u0004\u0010\u0000\u001a\f\u0012\u0006\u0012\u0004\u0018\u0001H\u0002\u0018\u00010\u0001\"\u0006\b\u0000\u0010\u0002\u0018\u0001\"\u0004\b\u0001\u0010\u0003H\n¢\u0006\u0004\b\u0004\u0010\u0005"}, m173d2 = {"<anonymous>", "", "T", "R", "invoke", "()[Ljava/lang/Object;"}, m172k = 3, m171mv = {1, 6, 0}, m169xi = CipherSuite.TLS_PSK_WITH_NULL_SHA256)
/* loaded from: classes.dex */
final class FlowKt__ZipKt$combine$5$1<T> extends Lambda implements Functions<T[]> {
    final /* synthetic */ Flow<T>[] $flows;

    /* JADX WARN: 'super' call moved to the top of the method (can break code semantics) */
    /* JADX WARN: Multi-variable type inference failed */
    public FlowKt__ZipKt$combine$5$1(Flow<? extends T>[] flowArr) {
        super(0);
        this.$flows = flowArr;
    }

    @Override // kotlin.jvm.functions.Functions
    public final T[] invoke() {
        int length = this.$flows.length;
        Intrinsics.reifiedOperationMarker(0, "T?");
        return (T[]) new Object[length];
    }
}