package org.bouncycastle.pqc.legacy.crypto.gmss.util;

import kotlin.UByte;
import org.bouncycastle.crypto.Digest;

/* loaded from: classes2.dex */
public class WinternitzOTSVerify {
    private int mdsize;
    private Digest messDigestOTS;

    /* renamed from: w */
    private int f1475w;

    public WinternitzOTSVerify(Digest digest, int i) {
        this.f1475w = i;
        this.messDigestOTS = digest;
        this.mdsize = digest.getDigestSize();
    }

    private void hashSignatureBlock(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        if (i2 < 1) {
            System.arraycopy(bArr, i, bArr2, i3, this.mdsize);
            return;
        }
        this.messDigestOTS.update(bArr, i, this.mdsize);
        while (true) {
            this.messDigestOTS.doFinal(bArr2, i3);
            i2--;
            if (i2 <= 0) {
                return;
            }
            this.messDigestOTS.update(bArr2, i3, this.mdsize);
        }
    }

    public byte[] Verify(byte[] bArr, byte[] bArr2) {
        int i;
        int i2;
        int i3;
        WinternitzOTSVerify winternitzOTSVerify = this;
        int i4 = winternitzOTSVerify.mdsize;
        byte[] bArr3 = new byte[i4];
        int i5 = 0;
        winternitzOTSVerify.messDigestOTS.update(bArr, 0, bArr.length);
        winternitzOTSVerify.messDigestOTS.doFinal(bArr3, 0);
        int i6 = winternitzOTSVerify.f1475w;
        int i7 = ((winternitzOTSVerify.mdsize << 3) + (i6 - 1)) / i6;
        int log = winternitzOTSVerify.getLog((i7 << i6) + 1);
        int i8 = winternitzOTSVerify.f1475w;
        int i9 = winternitzOTSVerify.mdsize;
        int i10 = i9 * ((((log + i8) - 1) / i8) + i7);
        if (i10 != bArr2.length) {
            return null;
        }
        byte[] bArr4 = new byte[i10];
        int i11 = 8;
        if (8 % i8 == 0) {
            int i12 = 8 / i8;
            int i13 = (1 << i8) - 1;
            int i14 = 0;
            int i15 = 0;
            int i16 = 0;
            while (i16 < i4) {
                int i17 = i15;
                int i18 = 0;
                while (i18 < i12) {
                    int i19 = bArr3[i16] & i13;
                    int i20 = i14 + i19;
                    int i21 = winternitzOTSVerify.mdsize;
                    int i22 = i16;
                    hashSignatureBlock(bArr2, i17 * i21, i13 - i19, bArr4, i17 * i21);
                    bArr3[i22] = (byte) (bArr3[i22] >>> winternitzOTSVerify.f1475w);
                    i17++;
                    i18++;
                    i14 = i20;
                    i16 = i22;
                    i12 = i12;
                }
                i16++;
                i15 = i17;
            }
            int i23 = i15;
            int i24 = (i7 << winternitzOTSVerify.f1475w) - i14;
            int i25 = 0;
            while (i25 < log) {
                int i26 = winternitzOTSVerify.mdsize;
                hashSignatureBlock(bArr2, i23 * i26, i13 - (i24 & i13), bArr4, i23 * i26);
                int i27 = winternitzOTSVerify.f1475w;
                i24 >>>= i27;
                i23++;
                i25 += i27;
            }
            i3 = 0;
            i = i10;
        } else {
            long j = 0;
            if (i8 < 8) {
                int i28 = i9 / i8;
                int i29 = (1 << i8) - 1;
                int i30 = 0;
                int i31 = 0;
                int i32 = 0;
                int i33 = 0;
                while (i33 < i28) {
                    int i34 = i30;
                    int i35 = i5;
                    long j2 = 0;
                    while (i35 < winternitzOTSVerify.f1475w) {
                        j2 ^= (bArr3[i34] & UByte.MAX_VALUE) << (i35 << 3);
                        i34++;
                        i35++;
                        log = log;
                    }
                    int i36 = log;
                    int i37 = i32;
                    int i38 = 0;
                    while (i38 < i11) {
                        int i39 = (int) (j2 & i29);
                        int i40 = i31 + i39;
                        int i41 = this.mdsize;
                        winternitzOTSVerify = this;
                        hashSignatureBlock(bArr2, i37 * i41, i29 - i39, bArr4, i37 * i41);
                        j2 >>>= winternitzOTSVerify.f1475w;
                        i37++;
                        i38++;
                        i29 = i29;
                        i11 = 8;
                        i33 = i33;
                        i31 = i40;
                    }
                    i33++;
                    i32 = i37;
                    i30 = i34;
                    log = i36;
                    i5 = 0;
                }
                int i42 = log;
                int i43 = i29;
                int i44 = winternitzOTSVerify.mdsize % winternitzOTSVerify.f1475w;
                int i45 = 0;
                while (i45 < i44) {
                    j ^= (bArr3[i30] & UByte.MAX_VALUE) << (i45 << 3);
                    i30++;
                    i45++;
                    i31 = i31;
                    i32 = i32;
                }
                int i46 = i32;
                int i47 = i44 << 3;
                int i48 = 0;
                while (i48 < i47) {
                    int i49 = (int) (j & i43);
                    int i50 = i31 + i49;
                    int i51 = winternitzOTSVerify.mdsize;
                    hashSignatureBlock(bArr2, i46 * i51, i43 - i49, bArr4, i46 * i51);
                    int i52 = winternitzOTSVerify.f1475w;
                    j >>>= i52;
                    i46++;
                    i48 += i52;
                    i31 = i50;
                }
                int i53 = (i7 << winternitzOTSVerify.f1475w) - i31;
                int i54 = 0;
                while (i54 < i42) {
                    int i55 = winternitzOTSVerify.mdsize;
                    hashSignatureBlock(bArr2, i46 * i55, i43 - (i53 & i43), bArr4, i46 * i55);
                    int i56 = winternitzOTSVerify.f1475w;
                    i53 >>>= i56;
                    i46++;
                    i54 += i56;
                }
            } else if (i8 < 57) {
                int i57 = (i9 << 3) - i8;
                int i58 = (1 << i8) - 1;
                byte[] bArr5 = new byte[i9];
                int i59 = 0;
                int i60 = 0;
                int i61 = 0;
                while (i59 <= i57) {
                    int i62 = i59 >>> 3;
                    int i63 = i59 % 8;
                    int i64 = i57;
                    int i65 = i59 + winternitzOTSVerify.f1475w;
                    int i66 = (i65 + 7) >>> 3;
                    long j3 = 0;
                    int i67 = 0;
                    while (i62 < i66) {
                        j3 ^= (bArr3[i62] & UByte.MAX_VALUE) << (i67 << 3);
                        i67++;
                        i62++;
                        i66 = i66;
                        i65 = i65;
                    }
                    int i68 = i65;
                    long j4 = j3 >>> i63;
                    int i69 = i10;
                    long j5 = i58;
                    long j6 = j4 & j5;
                    int i70 = i7;
                    i60 = (int) (i60 + j6);
                    int i71 = winternitzOTSVerify.mdsize;
                    System.arraycopy(bArr2, i61 * i71, bArr5, 0, i71);
                    for (long j7 = j6; j7 < j5; j7++) {
                        winternitzOTSVerify.messDigestOTS.update(bArr5, 0, i9);
                        winternitzOTSVerify.messDigestOTS.doFinal(bArr5, 0);
                    }
                    int i72 = winternitzOTSVerify.mdsize;
                    System.arraycopy(bArr5, 0, bArr4, i61 * i72, i72);
                    i61++;
                    i57 = i64;
                    i7 = i70;
                    i10 = i69;
                    i59 = i68;
                }
                int i73 = i7;
                i = i10;
                int i74 = i59 >>> 3;
                if (i74 < winternitzOTSVerify.mdsize) {
                    int i75 = i59 % 8;
                    int i76 = 0;
                    while (true) {
                        i2 = winternitzOTSVerify.mdsize;
                        if (i74 >= i2) {
                            break;
                        }
                        j ^= (bArr3[i74] & UByte.MAX_VALUE) << (i76 << 3);
                        i76++;
                        i74++;
                    }
                    long j8 = i58;
                    long j9 = (j >>> i75) & j8;
                    i60 = (int) (i60 + j9);
                    System.arraycopy(bArr2, i61 * i2, bArr5, 0, i2);
                    while (j9 < j8) {
                        winternitzOTSVerify.messDigestOTS.update(bArr5, 0, i9);
                        winternitzOTSVerify.messDigestOTS.doFinal(bArr5, 0);
                        j9++;
                    }
                    int i77 = winternitzOTSVerify.mdsize;
                    System.arraycopy(bArr5, 0, bArr4, i61 * i77, i77);
                    i61++;
                }
                int i78 = (i73 << winternitzOTSVerify.f1475w) - i60;
                int i79 = 0;
                while (i79 < log) {
                    int i80 = winternitzOTSVerify.mdsize;
                    System.arraycopy(bArr2, i61 * i80, bArr5, 0, i80);
                    for (long j10 = i78 & i58; j10 < i58; j10++) {
                        winternitzOTSVerify.messDigestOTS.update(bArr5, 0, i9);
                        winternitzOTSVerify.messDigestOTS.doFinal(bArr5, 0);
                    }
                    int i81 = winternitzOTSVerify.mdsize;
                    System.arraycopy(bArr5, 0, bArr4, i61 * i81, i81);
                    int i82 = winternitzOTSVerify.f1475w;
                    i78 >>>= i82;
                    i61++;
                    i79 += i82;
                }
                i3 = 0;
            }
            i = i10;
            i3 = 0;
        }
        winternitzOTSVerify.messDigestOTS.update(bArr4, i3, i);
        byte[] bArr6 = new byte[winternitzOTSVerify.mdsize];
        winternitzOTSVerify.messDigestOTS.doFinal(bArr6, i3);
        return bArr6;
    }

    public int getLog(int i) {
        int i2 = 1;
        int i3 = 2;
        while (i3 < i) {
            i3 <<= 1;
            i2++;
        }
        return i2;
    }

    public int getSignatureLength() {
        int digestSize = this.messDigestOTS.getDigestSize();
        int i = this.f1475w;
        int i2 = ((digestSize << 3) + (i - 1)) / i;
        int log = getLog((i2 << i) + 1);
        int i3 = this.f1475w;
        return digestSize * (i2 + (((log + i3) - 1) / i3));
    }
}