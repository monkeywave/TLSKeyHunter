package androidx.emoji2.text.flatbuffer;

import androidx.emoji2.text.flatbuffer.Utf8;
import java.nio.ByteBuffer;
import org.bouncycastle.asn1.BERTags;

/* loaded from: classes.dex */
public final class Utf8Safe extends Utf8 {
    private static int computeEncodedLength(CharSequence charSequence) {
        int length = charSequence.length();
        int i = 0;
        while (i < length && charSequence.charAt(i) < 128) {
            i++;
        }
        int i2 = length;
        while (true) {
            if (i < length) {
                char charAt = charSequence.charAt(i);
                if (charAt >= 2048) {
                    i2 += encodedLengthGeneral(charSequence, i);
                    break;
                }
                i2 += (127 - charAt) >>> 31;
                i++;
            } else {
                break;
            }
        }
        if (i2 >= length) {
            return i2;
        }
        throw new IllegalArgumentException("UTF-8 length does not fit in int: " + (i2 + 4294967296L));
    }

    private static int encodedLengthGeneral(CharSequence charSequence, int i) {
        int length = charSequence.length();
        int i2 = 0;
        while (i < length) {
            char charAt = charSequence.charAt(i);
            if (charAt < 2048) {
                i2 += (127 - charAt) >>> 31;
            } else {
                i2 += 2;
                if (55296 <= charAt && charAt <= 57343) {
                    if (Character.codePointAt(charSequence, i) < 65536) {
                        throw new UnpairedSurrogateException(i, length);
                    }
                    i++;
                }
            }
            i++;
        }
        return i2;
    }

    public static String decodeUtf8Array(byte[] bArr, int i, int i2) {
        if ((i | i2 | ((bArr.length - i) - i2)) < 0) {
            throw new ArrayIndexOutOfBoundsException(String.format("buffer length=%d, index=%d, size=%d", Integer.valueOf(bArr.length), Integer.valueOf(i), Integer.valueOf(i2)));
        }
        int i3 = i + i2;
        char[] cArr = new char[i2];
        int i4 = 0;
        while (i < i3) {
            byte b = bArr[i];
            if (!Utf8.DecodeUtil.isOneByte(b)) {
                break;
            }
            i++;
            Utf8.DecodeUtil.handleOneByte(b, cArr, i4);
            i4++;
        }
        int i5 = i4;
        while (i < i3) {
            int i6 = i + 1;
            byte b2 = bArr[i];
            if (Utf8.DecodeUtil.isOneByte(b2)) {
                int i7 = i5 + 1;
                Utf8.DecodeUtil.handleOneByte(b2, cArr, i5);
                while (i6 < i3) {
                    byte b3 = bArr[i6];
                    if (!Utf8.DecodeUtil.isOneByte(b3)) {
                        break;
                    }
                    i6++;
                    Utf8.DecodeUtil.handleOneByte(b3, cArr, i7);
                    i7++;
                }
                i5 = i7;
                i = i6;
            } else if (Utf8.DecodeUtil.isTwoBytes(b2)) {
                if (i6 >= i3) {
                    throw new IllegalArgumentException("Invalid UTF-8");
                }
                i += 2;
                Utf8.DecodeUtil.handleTwoBytes(b2, bArr[i6], cArr, i5);
                i5++;
            } else if (Utf8.DecodeUtil.isThreeBytes(b2)) {
                if (i6 >= i3 - 1) {
                    throw new IllegalArgumentException("Invalid UTF-8");
                }
                int i8 = i + 2;
                i += 3;
                Utf8.DecodeUtil.handleThreeBytes(b2, bArr[i6], bArr[i8], cArr, i5);
                i5++;
            } else if (i6 >= i3 - 2) {
                throw new IllegalArgumentException("Invalid UTF-8");
            } else {
                byte b4 = bArr[i6];
                int i9 = i + 3;
                i += 4;
                Utf8.DecodeUtil.handleFourBytes(b2, b4, bArr[i + 2], bArr[i9], cArr, i5);
                i5 += 2;
            }
        }
        return new String(cArr, 0, i5);
    }

    public static String decodeUtf8Buffer(ByteBuffer byteBuffer, int i, int i2) {
        if ((i | i2 | ((byteBuffer.limit() - i) - i2)) < 0) {
            throw new ArrayIndexOutOfBoundsException(String.format("buffer limit=%d, index=%d, limit=%d", Integer.valueOf(byteBuffer.limit()), Integer.valueOf(i), Integer.valueOf(i2)));
        }
        int i3 = i + i2;
        char[] cArr = new char[i2];
        int i4 = 0;
        while (i < i3) {
            byte b = byteBuffer.get(i);
            if (!Utf8.DecodeUtil.isOneByte(b)) {
                break;
            }
            i++;
            Utf8.DecodeUtil.handleOneByte(b, cArr, i4);
            i4++;
        }
        int i5 = i4;
        while (i < i3) {
            int i6 = i + 1;
            byte b2 = byteBuffer.get(i);
            if (Utf8.DecodeUtil.isOneByte(b2)) {
                int i7 = i5 + 1;
                Utf8.DecodeUtil.handleOneByte(b2, cArr, i5);
                while (i6 < i3) {
                    byte b3 = byteBuffer.get(i6);
                    if (!Utf8.DecodeUtil.isOneByte(b3)) {
                        break;
                    }
                    i6++;
                    Utf8.DecodeUtil.handleOneByte(b3, cArr, i7);
                    i7++;
                }
                i5 = i7;
                i = i6;
            } else if (Utf8.DecodeUtil.isTwoBytes(b2)) {
                if (i6 >= i3) {
                    throw new IllegalArgumentException("Invalid UTF-8");
                }
                i += 2;
                Utf8.DecodeUtil.handleTwoBytes(b2, byteBuffer.get(i6), cArr, i5);
                i5++;
            } else if (Utf8.DecodeUtil.isThreeBytes(b2)) {
                if (i6 >= i3 - 1) {
                    throw new IllegalArgumentException("Invalid UTF-8");
                }
                int i8 = i + 2;
                i += 3;
                Utf8.DecodeUtil.handleThreeBytes(b2, byteBuffer.get(i6), byteBuffer.get(i8), cArr, i5);
                i5++;
            } else if (i6 >= i3 - 2) {
                throw new IllegalArgumentException("Invalid UTF-8");
            } else {
                byte b4 = byteBuffer.get(i6);
                int i9 = i + 3;
                i += 4;
                Utf8.DecodeUtil.handleFourBytes(b2, b4, byteBuffer.get(i + 2), byteBuffer.get(i9), cArr, i5);
                i5 += 2;
            }
        }
        return new String(cArr, 0, i5);
    }

    @Override // androidx.emoji2.text.flatbuffer.Utf8
    public int encodedLength(CharSequence charSequence) {
        return computeEncodedLength(charSequence);
    }

    @Override // androidx.emoji2.text.flatbuffer.Utf8
    public String decodeUtf8(ByteBuffer byteBuffer, int i, int i2) throws IllegalArgumentException {
        if (byteBuffer.hasArray()) {
            return decodeUtf8Array(byteBuffer.array(), byteBuffer.arrayOffset() + i, i2);
        }
        return decodeUtf8Buffer(byteBuffer, i, i2);
    }

    private static void encodeUtf8Buffer(CharSequence charSequence, ByteBuffer byteBuffer) {
        int i;
        int length = charSequence.length();
        int position = byteBuffer.position();
        int i2 = 0;
        while (i2 < length) {
            try {
                char charAt = charSequence.charAt(i2);
                if (charAt >= 128) {
                    break;
                }
                byteBuffer.put(position + i2, (byte) charAt);
                i2++;
            } catch (IndexOutOfBoundsException unused) {
                throw new ArrayIndexOutOfBoundsException("Failed writing " + charSequence.charAt(i2) + " at index " + (byteBuffer.position() + Math.max(i2, (position - byteBuffer.position()) + 1)));
            }
        }
        if (i2 == length) {
            byteBuffer.position(position + i2);
            return;
        }
        position += i2;
        while (i2 < length) {
            char charAt2 = charSequence.charAt(i2);
            if (charAt2 < 128) {
                byteBuffer.put(position, (byte) charAt2);
            } else if (charAt2 < 2048) {
                int i3 = position + 1;
                try {
                    byteBuffer.put(position, (byte) ((charAt2 >>> 6) | 192));
                    byteBuffer.put(i3, (byte) ((charAt2 & '?') | 128));
                    position = i3;
                } catch (IndexOutOfBoundsException unused2) {
                    position = i3;
                    throw new ArrayIndexOutOfBoundsException("Failed writing " + charSequence.charAt(i2) + " at index " + (byteBuffer.position() + Math.max(i2, (position - byteBuffer.position()) + 1)));
                }
            } else if (charAt2 < 55296 || 57343 < charAt2) {
                int i4 = position + 1;
                byteBuffer.put(position, (byte) ((charAt2 >>> '\f') | BERTags.FLAGS));
                position += 2;
                byteBuffer.put(i4, (byte) (((charAt2 >>> 6) & 63) | 128));
                byteBuffer.put(position, (byte) ((charAt2 & '?') | 128));
            } else {
                int i5 = i2 + 1;
                if (i5 != length) {
                    try {
                        char charAt3 = charSequence.charAt(i5);
                        if (Character.isSurrogatePair(charAt2, charAt3)) {
                            int codePoint = Character.toCodePoint(charAt2, charAt3);
                            int i6 = position + 1;
                            try {
                                byteBuffer.put(position, (byte) ((codePoint >>> 18) | 240));
                                i = position + 2;
                            } catch (IndexOutOfBoundsException unused3) {
                                position = i6;
                                i2 = i5;
                                throw new ArrayIndexOutOfBoundsException("Failed writing " + charSequence.charAt(i2) + " at index " + (byteBuffer.position() + Math.max(i2, (position - byteBuffer.position()) + 1)));
                            }
                            try {
                                byteBuffer.put(i6, (byte) (((codePoint >>> 12) & 63) | 128));
                                position += 3;
                                byteBuffer.put(i, (byte) (((codePoint >>> 6) & 63) | 128));
                                byteBuffer.put(position, (byte) ((codePoint & 63) | 128));
                                i2 = i5;
                            } catch (IndexOutOfBoundsException unused4) {
                                i2 = i5;
                                position = i;
                                throw new ArrayIndexOutOfBoundsException("Failed writing " + charSequence.charAt(i2) + " at index " + (byteBuffer.position() + Math.max(i2, (position - byteBuffer.position()) + 1)));
                            }
                        } else {
                            i2 = i5;
                        }
                    } catch (IndexOutOfBoundsException unused5) {
                    }
                }
                throw new UnpairedSurrogateException(i2, length);
            }
            i2++;
            position++;
        }
        byteBuffer.position(position);
    }

    /* JADX WARN: Code restructure failed: missing block: B:12:0x001d, code lost:
        return r9 + r0;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    private static int encodeUtf8Array(java.lang.CharSequence r7, byte[] r8, int r9, int r10) {
        /*
            Method dump skipped, instructions count: 254
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: androidx.emoji2.text.flatbuffer.Utf8Safe.encodeUtf8Array(java.lang.CharSequence, byte[], int, int):int");
    }

    @Override // androidx.emoji2.text.flatbuffer.Utf8
    public void encodeUtf8(CharSequence charSequence, ByteBuffer byteBuffer) {
        if (byteBuffer.hasArray()) {
            int arrayOffset = byteBuffer.arrayOffset();
            byteBuffer.position(encodeUtf8Array(charSequence, byteBuffer.array(), byteBuffer.position() + arrayOffset, byteBuffer.remaining()) - arrayOffset);
            return;
        }
        encodeUtf8Buffer(charSequence, byteBuffer);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes.dex */
    public static class UnpairedSurrogateException extends IllegalArgumentException {
        UnpairedSurrogateException(int i, int i2) {
            super("Unpaired surrogate at index " + i + " of " + i2);
        }
    }
}