package org.bouncycastle.pqc.crypto.falcon;

import androidx.core.app.FrameMetricsAggregator;
import kotlin.UByte;
import org.bouncycastle.asn1.cmc.BodyPartID;

/* loaded from: classes2.dex */
class FalconCommon {
    static final int[] l2bound = {0, 101498, 208714, 428865, 892039, 1852696, 3842630, 7959734, 16468416, 34034726, 70265242};

    void hash_to_point_ct(SHAKE256 shake256, short[] sArr, int i, int i2, short[] sArr2, int i3) {
        int i4;
        short s;
        boolean z;
        int i5;
        boolean z2;
        short s2;
        short[] sArr3 = new short[63];
        int i6 = 1 << i2;
        int i7 = i6 << 1;
        short s3 = new short[]{0, 65, 67, 71, 77, 86, 100, 122, 154, 205, 287}[i2];
        int i8 = i6 + s3;
        int i9 = 0;
        for (int i10 = 0; i10 < i8; i10++) {
            byte[] bArr = new byte[2];
            shake256.inner_shake256_extract(bArr, 0, 2);
            int i11 = ((bArr[0] & UByte.MAX_VALUE) << 8) | (bArr[1] & UByte.MAX_VALUE);
            int i12 = i11 - ((((i11 - 24578) >>> 31) - 1) & 24578);
            int i13 = i12 - ((((i12 - 24578) >>> 31) - 1) & 24578);
            int i14 = (((i11 - 61445) >>> 31) - 1) | (i13 - ((((i13 - 12289) >>> 31) - 1) & 12289));
            if (i10 < i6) {
                sArr[i + i10] = (short) i14;
            } else if (i10 < i7) {
                sArr2[(i3 + i10) - i6] = (short) i14;
            } else {
                sArr3[i10 - i7] = (short) i14;
            }
        }
        int i15 = 1;
        while (i15 <= s3) {
            int i16 = i9;
            int i17 = i16;
            while (i16 < i8) {
                if (i16 < i6) {
                    i4 = i + i16;
                    s = sArr[i4];
                    z = true;
                } else if (i16 < i7) {
                    i4 = (i3 + i16) - i6;
                    s = sArr2[i4];
                    z = true;
                } else {
                    i4 = i16 - i7;
                    s = sArr3[i4];
                    z = true;
                }
                int i18 = i16 - i17;
                int i19 = (s >>> 15) - 1;
                i17 -= i19;
                if (i16 >= i15) {
                    int i20 = i16 - i15;
                    if (i20 < i6) {
                        i5 = (i + i16) - i15;
                        s2 = sArr[i5];
                        z2 = true;
                    } else if (i20 < i7) {
                        i5 = (i3 + i20) - i6;
                        s2 = sArr2[i5];
                        z2 = true;
                    } else {
                        i5 = i20 - i7;
                        z2 = true;
                        s2 = sArr3[i5];
                    }
                    int i21 = i19 & (-(((i18 & i15) + FrameMetricsAggregator.EVERY_DURATION) >> 9));
                    if (z) {
                        sArr[i4] = (short) (((s ^ s2) & i21) ^ s);
                    } else if (z) {
                        sArr2[i4] = (short) (((s ^ s2) & i21) ^ s);
                    } else {
                        sArr3[i4] = (short) (((s ^ s2) & i21) ^ s);
                    }
                    boolean z3 = z2;
                    if (z3) {
                        sArr[i5] = (short) (s2 ^ ((s ^ s2) & i21));
                    } else if (z3) {
                        sArr2[i5] = (short) (s2 ^ ((s ^ s2) & i21));
                    } else {
                        sArr3[i5] = (short) (s2 ^ ((s ^ s2) & i21));
                    }
                }
                i16++;
            }
            i15 <<= 1;
            i9 = 0;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void hash_to_point_vartime(SHAKE256 shake256, short[] sArr, int i, int i2) {
        int i3 = 1 << i2;
        while (i3 > 0) {
            byte[] bArr = new byte[2];
            shake256.inner_shake256_extract(bArr, 0, 2);
            int i4 = ((bArr[0] & UByte.MAX_VALUE) << 8) | (bArr[1] & UByte.MAX_VALUE);
            if (i4 < 61445) {
                while (i4 >= 12289) {
                    i4 -= 12289;
                }
                sArr[i] = (short) i4;
                i3--;
                i++;
            }
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int is_short(short[] sArr, int i, short[] sArr2, int i2, int i3) {
        int i4 = 1 << i3;
        int i5 = 0;
        int i6 = 0;
        for (int i7 = 0; i7 < i4; i7++) {
            short s = sArr[i + i7];
            int i8 = i5 + (s * s);
            int i9 = i6 | i8;
            short s2 = sArr2[i2 + i7];
            i5 = i8 + (s2 * s2);
            i6 = i9 | i5;
        }
        return (((long) ((-(i6 >>> 31)) | i5)) & BodyPartID.bodyIdMax) <= ((long) l2bound[i3]) ? 1 : 0;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int is_short_half(int i, short[] sArr, int i2, int i3) {
        int i4 = 1 << i3;
        int i5 = -(i >>> 31);
        for (int i6 = 0; i6 < i4; i6++) {
            short s = sArr[i2 + i6];
            i += s * s;
            i5 |= i;
        }
        return (((long) (i | (-(i5 >>> 31)))) & BodyPartID.bodyIdMax) <= ((long) l2bound[i3]) ? 1 : 0;
    }
}