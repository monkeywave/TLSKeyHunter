package androidx.core.graphics.drawable;

import android.graphics.Bitmap;
import android.net.Uri;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

@Metadata(m174d1 = {"\u0000\u0016\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0010\u0012\n\u0000\u001a\r\u0010\u0000\u001a\u00020\u0001*\u00020\u0002H\u0087\b\u001a\r\u0010\u0003\u001a\u00020\u0001*\u00020\u0002H\u0087\b\u001a\r\u0010\u0003\u001a\u00020\u0001*\u00020\u0004H\u0087\b\u001a\r\u0010\u0003\u001a\u00020\u0001*\u00020\u0005H\u0087\b¨\u0006\u0006"}, m173d2 = {"toAdaptiveIcon", "Landroid/graphics/drawable/Icon;", "Landroid/graphics/Bitmap;", "toIcon", "Landroid/net/Uri;", "", "core-ktx_release"}, m172k = 2, m171mv = {1, 7, 1}, m169xi = 48)
/* renamed from: androidx.core.graphics.drawable.IconKt */
/* loaded from: classes.dex */
public final class Icon {
    public static final android.graphics.drawable.Icon toAdaptiveIcon(Bitmap bitmap) {
        Intrinsics.checkNotNullParameter(bitmap, "<this>");
        android.graphics.drawable.Icon createWithAdaptiveBitmap = android.graphics.drawable.Icon.createWithAdaptiveBitmap(bitmap);
        Intrinsics.checkNotNullExpressionValue(createWithAdaptiveBitmap, "createWithAdaptiveBitmap(this)");
        return createWithAdaptiveBitmap;
    }

    public static final android.graphics.drawable.Icon toIcon(Bitmap bitmap) {
        Intrinsics.checkNotNullParameter(bitmap, "<this>");
        android.graphics.drawable.Icon createWithBitmap = android.graphics.drawable.Icon.createWithBitmap(bitmap);
        Intrinsics.checkNotNullExpressionValue(createWithBitmap, "createWithBitmap(this)");
        return createWithBitmap;
    }

    public static final android.graphics.drawable.Icon toIcon(Uri uri) {
        Intrinsics.checkNotNullParameter(uri, "<this>");
        android.graphics.drawable.Icon createWithContentUri = android.graphics.drawable.Icon.createWithContentUri(uri);
        Intrinsics.checkNotNullExpressionValue(createWithContentUri, "createWithContentUri(this)");
        return createWithContentUri;
    }

    public static final android.graphics.drawable.Icon toIcon(byte[] bArr) {
        Intrinsics.checkNotNullParameter(bArr, "<this>");
        android.graphics.drawable.Icon createWithData = android.graphics.drawable.Icon.createWithData(bArr, 0, bArr.length);
        Intrinsics.checkNotNullExpressionValue(createWithData, "createWithData(this, 0, size)");
        return createWithData;
    }
}