package androidx.core.text;

import android.text.Spanned;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000 \n\u0000\n\u0002\u0010\u0011\n\u0000\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0002\b\u0003\n\u0002\u0010\r\n\u0000\u001a:\u0010\u0000\u001a\n\u0012\u0006\b\u0001\u0012\u0002H\u00020\u0001\"\n\b\u0000\u0010\u0002\u0018\u0001*\u00020\u0003*\u00020\u00042\b\b\u0002\u0010\u0005\u001a\u00020\u00062\b\b\u0002\u0010\u0007\u001a\u00020\u0006H\u0086\b¢\u0006\u0002\u0010\b\u001a\r\u0010\t\u001a\u00020\u0004*\u00020\nH\u0086\b¨\u0006\u000b"}, m173d2 = {"getSpans", "", "T", "", "Landroid/text/Spanned;", "start", "", "end", "(Landroid/text/Spanned;II)[Ljava/lang/Object;", "toSpanned", "", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.text.SpannedStringKt */
/* loaded from: classes.dex */
public final class SpannedString {
    public static final Spanned toSpanned(CharSequence charSequence) {
        Intrinsics.checkNotNullParameter(charSequence, "<this>");
        android.text.SpannedString valueOf = android.text.SpannedString.valueOf(charSequence);
        Intrinsics.checkNotNullExpressionValue(valueOf, "valueOf(this)");
        return valueOf;
    }

    public static /* synthetic */ Object[] getSpans$default(Spanned spanned, int i, int i2, int i3, Object obj) {
        if ((i3 & 1) != 0) {
            i = 0;
        }
        if ((i3 & 2) != 0) {
            i2 = spanned.length();
        }
        Intrinsics.checkNotNullParameter(spanned, "<this>");
        Intrinsics.reifiedOperationMarker(4, "T");
        Object[] spans = spanned.getSpans(i, i2, Object.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(start, end, T::class.java)");
        return spans;
    }

    public static final /* synthetic */ <T> T[] getSpans(Spanned spanned, int i, int i2) {
        Intrinsics.checkNotNullParameter(spanned, "<this>");
        Intrinsics.reifiedOperationMarker(4, "T");
        Object[] spans = spanned.getSpans(i, i2, Object.class);
        Intrinsics.checkNotNullExpressionValue(spans, "getSpans(start, end, T::class.java)");
        return (T[]) spans;
    }
}