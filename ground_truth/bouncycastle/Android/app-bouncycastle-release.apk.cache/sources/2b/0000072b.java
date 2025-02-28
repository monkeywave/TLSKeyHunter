package androidx.core.view;

import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000$\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0010\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0000\bÃ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J \u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\u0006\u0010\u0007\u001a\u00020\b2\u0006\u0010\t\u001a\u00020\nH\u0007¨\u0006\u000b"}, m173d2 = {"Landroidx/core/view/Api16Impl;", "", "()V", "postOnAnimationDelayed", "", "view", "Landroid/view/View;", "action", "Ljava/lang/Runnable;", "delayInMillis", "", "core-ktx_release"}, m172k = 1, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.view.Api16Impl */
/* loaded from: classes.dex */
final class View {
    public static final View INSTANCE = new View();

    private View() {
    }

    @JvmStatic
    public static final void postOnAnimationDelayed(android.view.View view, Runnable action, long j) {
        Intrinsics.checkNotNullParameter(view, "view");
        Intrinsics.checkNotNullParameter(action, "action");
        view.postOnAnimationDelayed(action, j);
    }
}