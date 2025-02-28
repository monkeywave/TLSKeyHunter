package kotlinx.coroutines;

import kotlin.Metadata;
import kotlin.Unit;
import kotlin.jvm.functions.Functions;

/* compiled from: Runnable.kt */
@Metadata(m174d1 = {"\u0000\u0016\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0002\n\u0000\u001a\u001d\u0010\u0000\u001a\u00060\u0001j\u0002`\u00022\u000e\b\u0004\u0010\u0003\u001a\b\u0012\u0004\u0012\u00020\u00050\u0004H\u0086\b*\n\u0010\u0000\"\u00020\u00012\u00020\u0001¨\u0006\u0006"}, m173d2 = {"Runnable", "Ljava/lang/Runnable;", "Lkotlinx/coroutines/Runnable;", "block", "Lkotlin/Function0;", "", "kotlinx-coroutines-core"}, m172k = 2, m171mv = {1, 6, 0}, m169xi = 48)
/* loaded from: classes.dex */
public final class RunnableKt {
    public static final Runnable Runnable(final Functions<Unit> functions) {
        return new Runnable() { // from class: kotlinx.coroutines.RunnableKt$Runnable$1
            @Override // java.lang.Runnable
            public final void run() {
                functions.invoke();
            }
        };
    }
}