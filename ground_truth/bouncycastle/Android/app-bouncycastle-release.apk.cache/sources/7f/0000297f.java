package org.bouncycastle.pqc.crypto.falcon;

import kotlin.UByte;

/* loaded from: classes2.dex */
class FalconCodec {
    final byte[] max_fg_bits = {0, 8, 8, 8, 8, 8, 7, 7, 6, 6, 5};
    final byte[] max_FG_bits = {0, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};
    final byte[] max_sig_bits = {0, 10, 11, 11, 12, 12, 12, 12, 12, 12, 12};

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Code restructure failed: missing block: B:13:0x0037, code lost:
        if (r7 == 0) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:14:0x0039, code lost:
        if (r6 != 0) goto L22;
     */
    /* JADX WARN: Code restructure failed: missing block: B:15:0x003b, code lost:
        return 0;
     */
    /* JADX WARN: Code restructure failed: missing block: B:16:0x003c, code lost:
        r8 = r11 + r2;
     */
    /* JADX WARN: Code restructure failed: missing block: B:17:0x003e, code lost:
        if (r7 == 0) goto L27;
     */
    /* JADX WARN: Code restructure failed: missing block: B:18:0x0040, code lost:
        r6 = -r6;
     */
    /* JADX WARN: Code restructure failed: missing block: B:19:0x0041, code lost:
        r10[r8] = (short) r6;
        r2 = r2 + 1;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public int comp_decode(short[] r10, int r11, int r12, byte[] r13, int r14, int r15) {
        /*
            r9 = this;
            r0 = 1
            int r12 = r0 << r12
            r1 = 0
            r2 = r1
            r3 = r2
            r4 = r3
            r5 = r4
        L8:
            if (r2 >= r12) goto L4e
            if (r5 < r15) goto Ld
            return r1
        Ld:
            int r3 = r3 << 8
            int r6 = r14 + r5
            r6 = r13[r6]
            r6 = r6 & 255(0xff, float:3.57E-43)
            r3 = r3 | r6
            int r5 = r5 + 1
            int r6 = r3 >>> r4
            r7 = r6 & 128(0x80, float:1.8E-43)
            r6 = r6 & 127(0x7f, float:1.78E-43)
        L1e:
            if (r4 != 0) goto L30
            if (r5 < r15) goto L23
            return r1
        L23:
            int r3 = r3 << 8
            int r4 = r14 + r5
            r4 = r13[r4]
            r4 = r4 & 255(0xff, float:3.57E-43)
            r3 = r3 | r4
            int r5 = r5 + 1
            r4 = 8
        L30:
            int r4 = r4 + (-1)
            int r8 = r3 >>> r4
            r8 = r8 & r0
            if (r8 == 0) goto L47
            if (r7 == 0) goto L3c
            if (r6 != 0) goto L3c
            return r1
        L3c:
            int r8 = r11 + r2
            if (r7 == 0) goto L41
            int r6 = -r6
        L41:
            short r6 = (short) r6
            r10[r8] = r6
            int r2 = r2 + 1
            goto L8
        L47:
            int r6 = r6 + 128
            r8 = 2047(0x7ff, float:2.868E-42)
            if (r6 <= r8) goto L1e
            return r1
        L4e:
            int r10 = r0 << r4
            int r10 = r10 - r0
            r10 = r10 & r3
            if (r10 == 0) goto L55
            return r1
        L55:
            return r5
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.pqc.crypto.falcon.FalconCodec.comp_decode(short[], int, int, byte[], int, int):int");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int comp_encode(byte[] bArr, int i, int i2, short[] sArr, int i3, int i4) {
        int i5 = 1 << i4;
        for (int i6 = 0; i6 < i5; i6++) {
            short s = sArr[i3 + i6];
            if (s < -2047 || s > 2047) {
                return 0;
            }
        }
        int i7 = 0;
        int i8 = 0;
        int i9 = 0;
        for (int i10 = 0; i10 < i5; i10++) {
            int i11 = i8 << 1;
            short s2 = sArr[i3 + i10];
            int i12 = s2;
            if (s2 < 0) {
                i11 |= 1;
                i12 = -s2;
            }
            int i13 = (i12 >>> 7) + 1;
            i8 = (((i11 << 7) | (i12 & 127)) << i13) | 1;
            i7 = i7 + 8 + i13;
            while (i7 >= 8) {
                i7 -= 8;
                if (bArr != null) {
                    if (i9 >= i2) {
                        return 0;
                    }
                    bArr[i + i9] = (byte) (i8 >>> i7);
                }
                i9++;
            }
        }
        if (i7 > 0) {
            if (bArr != null) {
                if (i9 >= i2) {
                    return 0;
                }
                bArr[i + i9] = (byte) (i8 << (8 - i7));
            }
            return i9 + 1;
        }
        return i9;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int modq_decode(short[] sArr, int i, int i2, byte[] bArr, int i3, int i4) {
        int i5 = 1 << i2;
        int i6 = ((i5 * 14) + 7) >> 3;
        if (i6 > i4) {
            return 0;
        }
        int i7 = 0;
        int i8 = 0;
        int i9 = 0;
        while (i7 < i5) {
            int i10 = i3 + 1;
            i8 = (i8 << 8) | (bArr[i3] & UByte.MAX_VALUE);
            int i11 = i9 + 8;
            if (i11 >= 14) {
                i9 -= 6;
                int i12 = (i8 >>> i9) & 16383;
                if (i12 >= 12289) {
                    return 0;
                }
                sArr[i + i7] = (short) i12;
                i7++;
            } else {
                i9 = i11;
            }
            i3 = i10;
        }
        if ((((1 << i9) - 1) & i8) != 0) {
            return 0;
        }
        return i6;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int modq_encode(byte[] bArr, int i, int i2, short[] sArr, int i3, int i4) {
        int i5 = 1 << i4;
        for (int i6 = 0; i6 < i5; i6++) {
            if ((65535 & sArr[i3 + i6]) >= 12289) {
                return 0;
            }
        }
        int i7 = ((i5 * 14) + 7) >> 3;
        if (bArr == null) {
            return i7;
        }
        if (i7 > i2) {
            return 0;
        }
        int i8 = 0;
        int i9 = 0;
        for (int i10 = 0; i10 < i5; i10++) {
            i9 = (i9 << 14) | (sArr[i3 + i10] & 65535);
            i8 += 14;
            while (i8 >= 8) {
                i8 -= 8;
                bArr[i] = (byte) (i9 >> i8);
                i++;
            }
        }
        if (i8 > 0) {
            bArr[i] = (byte) (i9 << (8 - i8));
        }
        return i7;
    }

    int trim_i16_decode(short[] sArr, int i, int i2, int i3, byte[] bArr, int i4, int i5) {
        int i6 = 1 << i2;
        int i7 = ((i6 * i3) + 7) >> 3;
        if (i7 > i5) {
            return 0;
        }
        int i8 = (1 << i3) - 1;
        int i9 = 1 << (i3 - 1);
        int i10 = i4;
        int i11 = 0;
        int i12 = 0;
        int i13 = 0;
        while (i11 < i6) {
            int i14 = i10 + 1;
            i12 = (i12 << 8) | (bArr[i10] & 255);
            i13 += 8;
            while (i13 >= i3 && i11 < i6) {
                i13 -= i3;
                int i15 = (i12 >>> i13) & i8;
                int i16 = i15 | (-(i15 & i9));
                if (i16 == (-i9)) {
                    return 0;
                }
                sArr[i + i11] = (short) (i16 | (-(i16 & i9)));
                i11++;
            }
            i10 = i14;
        }
        if ((((1 << i13) - 1) & i12) != 0) {
            return 0;
        }
        return i7;
    }

    int trim_i16_encode(byte[] bArr, int i, int i2, short[] sArr, int i3, int i4, int i5) {
        int i6 = 1 << i4;
        int i7 = (1 << (i5 - 1)) - 1;
        int i8 = -i7;
        for (int i9 = 0; i9 < i6; i9++) {
            short s = sArr[i3 + i9];
            if (s < i8 || s > i7) {
                return 0;
            }
        }
        int i10 = ((i6 * i5) + 7) >> 3;
        if (bArr == null) {
            return i10;
        }
        if (i10 > i2) {
            return 0;
        }
        int i11 = (1 << i5) - 1;
        int i12 = 0;
        int i13 = 0;
        for (int i14 = 0; i14 < i6; i14++) {
            i13 = (i13 << i5) | (sArr[i3 + i14] & 4095 & i11);
            i12 += i5;
            while (i12 >= 8) {
                i12 -= 8;
                bArr[i] = (byte) (i13 >> i12);
                i++;
            }
        }
        if (i12 > 0) {
            bArr[i] = (byte) (i13 << (8 - i12));
        }
        return i10;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int trim_i8_decode(byte[] bArr, int i, int i2, int i3, byte[] bArr2, int i4, int i5) {
        int i6 = 1 << i2;
        int i7 = ((i6 * i3) + 7) >> 3;
        if (i7 > i5) {
            return 0;
        }
        int i8 = (1 << i3) - 1;
        int i9 = 1 << (i3 - 1);
        int i10 = i4;
        int i11 = 0;
        int i12 = 0;
        int i13 = 0;
        while (i11 < i6) {
            int i14 = i10 + 1;
            i12 = (i12 << 8) | (bArr2[i10] & 255);
            i13 += 8;
            while (i13 >= i3 && i11 < i6) {
                i13 -= i3;
                int i15 = (i12 >>> i13) & i8;
                int i16 = i15 | (-(i15 & i9));
                if (i16 == (-i9)) {
                    return 0;
                }
                bArr[i + i11] = (byte) i16;
                i11++;
            }
            i10 = i14;
        }
        if ((((1 << i13) - 1) & i12) != 0) {
            return 0;
        }
        return i7;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int trim_i8_encode(byte[] bArr, int i, int i2, byte[] bArr2, int i3, int i4, int i5) {
        int i6 = 1 << i4;
        int i7 = (1 << (i5 - 1)) - 1;
        int i8 = -i7;
        for (int i9 = 0; i9 < i6; i9++) {
            int i10 = bArr2[i3 + i9];
            if (i10 < i8 || i10 > i7) {
                return 0;
            }
        }
        int i11 = ((i6 * i5) + 7) >> 3;
        if (bArr == null) {
            return i11;
        }
        if (i11 > i2) {
            return 0;
        }
        int i12 = (1 << i5) - 1;
        int i13 = 0;
        int i14 = 0;
        for (int i15 = 0; i15 < i6; i15++) {
            i14 = (i14 << i5) | (bArr2[i3 + i15] & 65535 & i12);
            i13 += i5;
            while (i13 >= 8) {
                i13 -= 8;
                bArr[i] = (byte) (i14 >>> i13);
                i++;
            }
        }
        if (i13 > 0) {
            bArr[i] = (byte) (i14 << (8 - i13));
        }
        return i11;
    }
}