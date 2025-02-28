package kotlin.p004io.encoding;

import java.io.InputStream;
import java.io.OutputStream;
import kotlin.Metadata;
import kotlin.jvm.internal.Intrinsics;

/* compiled from: Base64IOStream.kt */
@Metadata(m174d1 = {"\u0000\u0014\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\u001a\u0014\u0010\u0000\u001a\u00020\u0001*\u00020\u00012\u0006\u0010\u0002\u001a\u00020\u0003H\u0007\u001a\u0014\u0010\u0004\u001a\u00020\u0005*\u00020\u00052\u0006\u0010\u0002\u001a\u00020\u0003H\u0007¨\u0006\u0006"}, m173d2 = {"decodingWith", "Ljava/io/InputStream;", "base64", "Lkotlin/io/encoding/Base64;", "encodingWith", "Ljava/io/OutputStream;", "kotlin-stdlib"}, m172k = 5, m171mv = {1, 8, 0}, m169xi = 49, m168xs = "kotlin/io/encoding/StreamEncodingKt")
/* renamed from: kotlin.io.encoding.StreamEncodingKt__Base64IOStreamKt */
/* loaded from: classes.dex */
class StreamEncodingKt__Base64IOStreamKt {
    public static final InputStream decodingWith(InputStream inputStream, Base64 base64) {
        Intrinsics.checkNotNullParameter(inputStream, "<this>");
        Intrinsics.checkNotNullParameter(base64, "base64");
        return new Base64IOStream(inputStream, base64);
    }

    public static final OutputStream encodingWith(OutputStream outputStream, Base64 base64) {
        Intrinsics.checkNotNullParameter(outputStream, "<this>");
        Intrinsics.checkNotNullParameter(base64, "base64");
        return new EncodeOutputStream(outputStream, base64);
    }
}