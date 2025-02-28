package androidx.core.util;

import android.util.SizeF;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000\u001a\n\u0000\n\u0002\u0010\b\n\u0002\u0018\u0002\n\u0002\u0010\u0007\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\b\u0002\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0087\n\u001a\r\u0010\u0000\u001a\u00020\u0003*\u00020\u0004H\u0087\n\u001a\r\u0010\u0000\u001a\u00020\u0003*\u00020\u0005H\u0086\n\u001a\r\u0010\u0006\u001a\u00020\u0001*\u00020\u0002H\u0087\n\u001a\r\u0010\u0006\u001a\u00020\u0003*\u00020\u0004H\u0087\n\u001a\r\u0010\u0006\u001a\u00020\u0003*\u00020\u0005H\u0086\n¨\u0006\u0007"}, m173d2 = {"component1", "", "Landroid/util/Size;", "", "Landroid/util/SizeF;", "Landroidx/core/util/SizeFCompat;", "component2", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.util.SizeKt */
/* loaded from: classes.dex */
public final class Size {
    public static final int component1(android.util.Size size) {
        Intrinsics.checkNotNullParameter(size, "<this>");
        return size.getWidth();
    }

    public static final int component2(android.util.Size size) {
        Intrinsics.checkNotNullParameter(size, "<this>");
        return size.getHeight();
    }

    public static final float component1(SizeF sizeF) {
        Intrinsics.checkNotNullParameter(sizeF, "<this>");
        return sizeF.getWidth();
    }

    public static final float component2(SizeF sizeF) {
        Intrinsics.checkNotNullParameter(sizeF, "<this>");
        return sizeF.getHeight();
    }

    public static final float component1(SizeFCompat sizeFCompat) {
        Intrinsics.checkNotNullParameter(sizeFCompat, "<this>");
        return sizeFCompat.getWidth();
    }

    public static final float component2(SizeFCompat sizeFCompat) {
        Intrinsics.checkNotNullParameter(sizeFCompat, "<this>");
        return sizeFCompat.getHeight();
    }
}