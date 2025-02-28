package androidx.core.text;

import android.text.TextUtils;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000\u0012\n\u0000\n\u0002\u0010\u000b\n\u0002\u0010\r\n\u0000\n\u0002\u0010\b\n\u0000\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0086\b\u001a\r\u0010\u0003\u001a\u00020\u0004*\u00020\u0002H\u0086\b¨\u0006\u0005"}, m173d2 = {"isDigitsOnly", "", "", "trimmedLength", "", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.text.CharSequenceKt */
/* loaded from: classes.dex */
public final class CharSequence {
    public static final boolean isDigitsOnly(java.lang.CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        return TextUtils.isDigitsOnly(charSequence);
    }

    public static final int trimmedLength(java.lang.CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        return TextUtils.getTrimmedLength(charSequence);
    }
}