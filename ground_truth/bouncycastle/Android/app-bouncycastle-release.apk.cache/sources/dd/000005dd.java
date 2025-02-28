package androidx.core.graphics;

import android.graphics.PorterDuff;
import android.graphics.PorterDuffColorFilter;
import android.graphics.PorterDuffXfermode;
import androidx.constraintlayout.core.motion.utils.TypedValues;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000\u0018\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\n\u0002\u0018\u0002\n\u0000\u001a\u0015\u0010\u0000\u001a\u00020\u0001*\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0086\b\u001a\r\u0010\u0005\u001a\u00020\u0006*\u00020\u0002H\u0086\b¨\u0006\u0007"}, m173d2 = {"toColorFilter", "Landroid/graphics/PorterDuffColorFilter;", "Landroid/graphics/PorterDuff$Mode;", TypedValues.Custom.S_COLOR, "", "toXfermode", "Landroid/graphics/PorterDuffXfermode;", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.graphics.PorterDuffKt */
/* loaded from: classes.dex */
public final class PorterDuff {
    public static final PorterDuffXfermode toXfermode(PorterDuff.Mode mode) {
        Intrinsics.checkNotNullParameter(mode, "<this>");
        return new PorterDuffXfermode(mode);
    }

    public static final PorterDuffColorFilter toColorFilter(PorterDuff.Mode mode, int i) {
        Intrinsics.checkNotNullParameter(mode, "<this>");
        return new PorterDuffColorFilter(i, mode);
    }
}