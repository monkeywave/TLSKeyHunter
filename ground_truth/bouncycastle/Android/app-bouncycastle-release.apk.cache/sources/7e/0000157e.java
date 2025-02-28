package kotlin.system;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Functions;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000\u0014\n\u0000\n\u0002\u0010\t\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0002\b\u0002\u001a'\u0010\u0000\u001a\u00020\u00012\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003H\u0086\bø\u0001\u0000\u0082\u0002\n\n\b\b\u0001\u0012\u0002\u0010\u0001 \u0001\u001a'\u0010\u0005\u001a\u00020\u00012\f\u0010\u0002\u001a\b\u0012\u0004\u0012\u00020\u00040\u0003H\u0086\bø\u0001\u0000\u0082\u0002\n\n\b\b\u0001\u0012\u0002\u0010\u0001 \u0001\u0082\u0002\u0007\n\u0005\b\u009920\u0001¨\u0006\u0006"}, m173d2 = {"measureNanoTime", "", "block", "Lkotlin/Function0;", "", "measureTimeMillis", "kotlin-stdlib"}, m172k = 2, m171mv = {1, 8, 0}, m169xi = 48)
/* renamed from: kotlin.system.TimingKt */
/* loaded from: classes.dex */
public final class Timing {
    public static final long measureTimeMillis(Functions<Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        long currentTimeMillis = System.currentTimeMillis();
        block.invoke();
        return System.currentTimeMillis() - currentTimeMillis;
    }

    public static final long measureNanoTime(Functions<Unit> block) {
        Intrinsics.checkNotNullParameter(block, "block");
        long nanoTime = System.nanoTime();
        block.invoke();
        return System.nanoTime() - nanoTime;
    }
}