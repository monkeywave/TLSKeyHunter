package androidx.core.content.res;

import android.graphics.Typeface;
import kotlin.Metadata;
import kotlin.jvm.JvmStatic;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\b\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\b\n\u0000\bÃ\u0002\u0018\u00002\u00020\u0001B\u0007\b\u0002¢\u0006\u0002\u0010\u0002J\u001a\u0010\u0003\u001a\u00020\u00042\u0006\u0010\u0005\u001a\u00020\u00062\b\b\u0001\u0010\u0007\u001a\u00020\bH\u0007¨\u0006\t"}, m173d2 = {"Landroidx/core/content/res/TypedArrayApi26ImplKt;", "", "()V", "getFont", "Landroid/graphics/Typeface;", "typedArray", "Landroid/content/res/TypedArray;", "index", "", "core-ktx_release"}, m172k = 1, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.content.res.TypedArrayApi26ImplKt */
/* loaded from: classes.dex */
final class TypedArray {
    public static final TypedArray INSTANCE = new TypedArray();

    private TypedArray() {
    }

    @JvmStatic
    public static final Typeface getFont(android.content.res.TypedArray typedArray, int i) {
        Intrinsics.checkNotNullParameter(typedArray, "typedArray");
        Typeface font = typedArray.getFont(i);
        Intrinsics.checkNotNull(font);
        return font;
    }
}