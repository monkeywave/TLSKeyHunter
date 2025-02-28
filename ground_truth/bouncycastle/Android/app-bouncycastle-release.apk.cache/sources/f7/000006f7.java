package androidx.core.util;

import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000\u0018\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0006\n\u0002\u0010\u0007\n\u0002\u0010\n\n\u0002\u0010\u000e\n\u0000\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0087\b\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0003H\u0087\b\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0004H\u0087\b\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0005H\u0087\b¨\u0006\u0006"}, m173d2 = {"toHalf", "Landroid/util/Half;", "", "", "", "", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.util.HalfKt */
/* loaded from: classes.dex */
public final class Half {
    public static final android.util.Half toHalf(short s) {
        android.util.Half valueOf = android.util.Half.valueOf(s);
        Intrinsics.checkNotNullExpressionValue(valueOf, "valueOf(this)");
        return valueOf;
    }

    public static final android.util.Half toHalf(float f) {
        android.util.Half valueOf = android.util.Half.valueOf(f);
        Intrinsics.checkNotNullExpressionValue(valueOf, "valueOf(this)");
        return valueOf;
    }

    public static final android.util.Half toHalf(String str) {
        Intrinsics.checkNotNullParameter(str, "<this>");
        android.util.Half valueOf = android.util.Half.valueOf(str);
        Intrinsics.checkNotNullExpressionValue(valueOf, "valueOf(this)");
        return valueOf;
    }

    public static final android.util.Half toHalf(double d) {
        android.util.Half valueOf = android.util.Half.valueOf((float) d);
        Intrinsics.checkNotNullExpressionValue(valueOf, "valueOf(this)");
        return valueOf;
    }
}