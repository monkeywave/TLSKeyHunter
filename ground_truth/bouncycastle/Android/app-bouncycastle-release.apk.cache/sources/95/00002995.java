package org.bouncycastle.pqc.crypto.frodo;

import java.security.SecureRandom;
import kotlin.UByte;
import org.bouncycastle.crypto.Xof;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class FrodoEngine {
    private static final int len_chi = 16;
    private static final int len_chi_bytes = 2;
    private static final int len_seedA = 128;
    private static final int len_seedA_bytes = 16;
    private static final int len_z = 128;
    private static final int len_z_bytes = 16;
    private static final int mbar = 8;
    static final int nbar = 8;

    /* renamed from: B */
    private final int f1250B;

    /* renamed from: D */
    private final int f1251D;
    private final short[] T_chi;
    private final Xof digest;
    private final FrodoMatrixGenerator gen;
    private final int len_ct_bytes;
    private final int len_k;
    private final int len_k_bytes;
    private final int len_mu;
    private final int len_mu_bytes;
    private final int len_pk_bytes;
    private final int len_pkh;
    private final int len_pkh_bytes;
    private final int len_s;
    private final int len_s_bytes;
    private final int len_seedSE;
    private final int len_seedSE_bytes;
    private final int len_sk_bytes;
    private final int len_ss;
    private final int len_ss_bytes;

    /* renamed from: n */
    private final int f1252n;

    /* renamed from: q */
    private final int f1253q;

    public FrodoEngine(int i, int i2, int i3, short[] sArr, Xof xof, FrodoMatrixGenerator frodoMatrixGenerator) {
        this.f1252n = i;
        this.f1251D = i2;
        this.f1253q = 1 << i2;
        this.f1250B = i3;
        int i4 = i3 * 64;
        this.len_mu = i4;
        this.len_seedSE = i4;
        this.len_s = i4;
        this.len_k = i4;
        this.len_pkh = i4;
        this.len_ss = i4;
        this.len_mu_bytes = i4 / 8;
        this.len_seedSE_bytes = i4 / 8;
        int i5 = i4 / 8;
        this.len_s_bytes = i5;
        this.len_k_bytes = i4 / 8;
        int i6 = i4 / 8;
        this.len_pkh_bytes = i6;
        this.len_ss_bytes = i4 / 8;
        int i7 = ((i2 * i) * 8) / 8;
        this.len_ct_bytes = ((i2 * 64) / 8) + i7;
        int i8 = i7 + 16;
        this.len_pk_bytes = i8;
        this.len_sk_bytes = i5 + i8 + (i * 16) + i6;
        this.T_chi = sArr;
        this.digest = xof;
        this.gen = frodoMatrixGenerator;
    }

    private byte[] ctselect(byte[] bArr, byte[] bArr2, short s) {
        byte[] bArr3 = new byte[bArr.length];
        for (int i = 0; i < bArr.length; i++) {
            bArr3[i] = (byte) (((~s) & bArr[i] & 255) | (bArr2[i] & s & 255));
        }
        return bArr3;
    }

    private short ctverify(short[] sArr, short[] sArr2, short[] sArr3, short[] sArr4) {
        short s = 0;
        for (short s2 = 0; s2 < sArr.length; s2 = (short) (s2 + 1)) {
            s = (short) (s | (sArr[s2] ^ sArr3[s2]));
        }
        for (short s3 = 0; s3 < sArr2.length; s3 = (short) (s3 + 1)) {
            s = (short) ((sArr2[s3] ^ sArr4[s3]) | s);
        }
        return s == 0 ? (short) 0 : (short) -1;
    }

    private byte[] decode(short[] sArr) {
        int i;
        int i2 = this.f1250B;
        short s = (short) ((1 << i2) - 1);
        short s2 = (short) ((1 << this.f1251D) - 1);
        byte[] bArr = new byte[i2 * 8];
        int i3 = 0;
        for (int i4 = 0; i4 < 8; i4++) {
            long j = 0;
            for (int i5 = 0; i5 < 8; i5++) {
                int i6 = this.f1251D;
                j |= (((short) (((sArr[i3] & s2) + (1 << ((i6 - i) - 1))) >> (i6 - i))) & s) << (this.f1250B * i5);
                i3++;
            }
            int i7 = 0;
            while (true) {
                int i8 = this.f1250B;
                if (i7 < i8) {
                    bArr[(i8 * i4) + i7] = (byte) ((j >> (i7 * 8)) & 255);
                    i7++;
                }
            }
        }
        return bArr;
    }

    private short[] encode(byte[] bArr) {
        int i;
        short[] sArr = new short[64];
        int i2 = 0;
        int i3 = 0;
        for (int i4 = 0; i4 < 8; i4++) {
            for (int i5 = 0; i5 < 8; i5++) {
                int i6 = 0;
                int i7 = 0;
                while (true) {
                    i = this.f1250B;
                    if (i6 < i) {
                        i7 += ((bArr[i2] >>> i3) & 1) << i6;
                        int i8 = i3 + 1;
                        i2 += i8 >>> 3;
                        i3 = i8 & 7;
                        i6++;
                    }
                }
                sArr[(i4 * 8) + i5] = (short) (i7 * (this.f1253q / (1 << i)));
            }
        }
        return sArr;
    }

    private short[] matrix_add(short[] sArr, short[] sArr2, int i, int i2) {
        int i3 = this.f1253q - 1;
        short[] sArr3 = new short[i * i2];
        for (int i4 = 0; i4 < i; i4++) {
            for (int i5 = 0; i5 < i2; i5++) {
                int i6 = (i4 * i2) + i5;
                sArr3[i6] = (short) ((sArr[i6] + sArr2[i6]) & i3);
            }
        }
        return sArr3;
    }

    private short[] matrix_mul(short[] sArr, int i, int i2, short[] sArr2, int i3, int i4) {
        int i5 = this.f1253q - 1;
        short[] sArr3 = new short[i * i4];
        for (int i6 = 0; i6 < i; i6++) {
            for (int i7 = 0; i7 < i4; i7++) {
                int i8 = 0;
                for (int i9 = 0; i9 < i2; i9++) {
                    i8 += sArr[(i6 * i2) + i9] * sArr2[(i9 * i4) + i7];
                }
                sArr3[(i6 * i4) + i7] = (short) (i8 & i5);
            }
        }
        return sArr3;
    }

    private short[] matrix_sub(short[] sArr, short[] sArr2, int i, int i2) {
        int i3 = this.f1253q - 1;
        short[] sArr3 = new short[i * i2];
        for (int i4 = 0; i4 < i; i4++) {
            for (int i5 = 0; i5 < i2; i5++) {
                int i6 = (i4 * i2) + i5;
                sArr3[i6] = (short) ((sArr[i6] - sArr2[i6]) & i3);
            }
        }
        return sArr3;
    }

    private short[] matrix_transpose(short[] sArr, int i, int i2) {
        short[] sArr2 = new short[i * i2];
        for (int i3 = 0; i3 < i2; i3++) {
            for (int i4 = 0; i4 < i; i4++) {
                sArr2[(i3 * i) + i4] = sArr[(i4 * i2) + i3];
            }
        }
        return sArr2;
    }

    private byte[] pack(short[] sArr) {
        int length = sArr.length;
        int i = (this.f1251D * length) / 8;
        byte[] bArr = new byte[i];
        short s = 0;
        short s2 = 0;
        byte b = 0;
        short s3 = 0;
        while (s < i && (s2 < length || (s2 == length && b > 0))) {
            byte b2 = 0;
            while (b2 < 8) {
                int i2 = 8 - b2;
                int min = Math.min(i2, (int) b);
                int i3 = b - min;
                bArr[s] = (byte) (bArr[s] + (((byte) (((short) ((1 << min) - 1)) & (s3 >> i3))) << (i2 - min)));
                b2 = (byte) (b2 + min);
                b = (byte) i3;
                if (b == 0) {
                    if (s2 >= length) {
                        break;
                    }
                    short s4 = sArr[s2];
                    s2 = (short) (s2 + 1);
                    s3 = s4;
                    b = (byte) this.f1251D;
                }
            }
            if (b2 == 8) {
                s = (short) (s + 1);
            }
        }
        return bArr;
    }

    private short sample(short s) {
        int i = s & 65535;
        short s2 = (short) (i >>> 1);
        int i2 = 0;
        short s3 = 0;
        while (true) {
            short[] sArr = this.T_chi;
            if (i2 >= sArr.length) {
                break;
            }
            if (s2 > sArr[i2]) {
                s3 = (short) (s3 + 1);
            }
            i2++;
        }
        return i % 2 == 1 ? (short) ((s3 * (-1)) & 65535) : s3;
    }

    private short[] sample_matrix(short[] sArr, int i, int i2, int i3) {
        short[] sArr2 = new short[i2 * i3];
        for (int i4 = 0; i4 < i2; i4++) {
            for (int i5 = 0; i5 < i3; i5++) {
                int i6 = (i4 * i3) + i5;
                sArr2[i6] = sample(sArr[i6 + i]);
            }
        }
        return sArr2;
    }

    private short[] unpack(byte[] bArr, int i, int i2) {
        int i3 = i * i2;
        short[] sArr = new short[i3];
        short s = 0;
        short s2 = 0;
        byte b = 0;
        byte b2 = 0;
        while (s < i3 && (s2 < bArr.length || (s2 == bArr.length && b > 0))) {
            byte b3 = 0;
            while (true) {
                int i4 = this.f1251D;
                if (b3 >= i4) {
                    break;
                }
                int min = Math.min(i4 - b3, (int) b);
                short s3 = (short) (((1 << min) - 1) & 65535);
                sArr[s] = (short) (((sArr[s] & 65535) + ((((byte) ((((b2 & UByte.MAX_VALUE) >>> ((b & UByte.MAX_VALUE) - min)) & (s3 & 65535)) & 255)) & UByte.MAX_VALUE) << ((this.f1251D - (b3 & UByte.MAX_VALUE)) - min))) & 65535);
                b3 = (byte) (b3 + min);
                byte b4 = (byte) (b - min);
                byte b5 = (byte) ((~(s3 << b4)) & b2);
                if (b4 != 0) {
                    b2 = b5;
                    b = b4;
                } else if (s2 >= bArr.length) {
                    b2 = b5;
                    b = b4;
                    break;
                } else {
                    byte b6 = bArr[s2];
                    s2 = (short) (s2 + 1);
                    b = 8;
                    b2 = b6;
                }
            }
            if (b3 == this.f1251D) {
                s = (short) (s + 1);
            }
        }
        return sArr;
    }

    public int getCipherTextSize() {
        return this.len_ct_bytes;
    }

    public int getPrivateKeySize() {
        return this.len_sk_bytes;
    }

    public int getPublicKeySize() {
        return this.len_pk_bytes;
    }

    public int getSessionKeySize() {
        return this.len_ss_bytes;
    }

    public void kem_dec(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        int i = ((this.f1252n * 8) * this.f1251D) / 8;
        byte[] copyOfRange = Arrays.copyOfRange(bArr2, 0, i);
        byte[] copyOfRange2 = Arrays.copyOfRange(bArr2, i, ((this.f1251D * 64) / 8) + i);
        int i2 = this.len_s_bytes;
        byte[] copyOfRange3 = Arrays.copyOfRange(bArr3, 0, i2);
        int i3 = i2 + 16;
        byte[] copyOfRange4 = Arrays.copyOfRange(bArr3, i2, i3);
        int i4 = (((this.f1251D * this.f1252n) * 8) / 8) + i3;
        byte[] copyOfRange5 = Arrays.copyOfRange(bArr3, i3, i4);
        int i5 = ((this.f1252n * 128) / 8) + i4;
        byte[] copyOfRange6 = Arrays.copyOfRange(bArr3, i4, i5);
        short[] sArr = new short[this.f1252n * 8];
        for (int i6 = 0; i6 < 8; i6++) {
            int i7 = 0;
            while (true) {
                int i8 = this.f1252n;
                if (i7 < i8) {
                    sArr[(i6 * i8) + i7] = Pack.littleEndianToShort(copyOfRange6, (i8 * i6 * 2) + (i7 * 2));
                    i7++;
                }
            }
        }
        short[] matrix_transpose = matrix_transpose(sArr, 8, this.f1252n);
        byte[] copyOfRange7 = Arrays.copyOfRange(bArr3, i5, this.len_pkh_bytes + i5);
        short[] unpack = unpack(copyOfRange, 8, this.f1252n);
        short[] unpack2 = unpack(copyOfRange2, 8, 8);
        int i9 = this.f1252n;
        byte[] decode = decode(matrix_sub(unpack2, matrix_mul(unpack, 8, i9, matrix_transpose, i9, 8), 8, 8));
        byte[] bArr4 = new byte[this.len_seedSE_bytes + this.len_k_bytes];
        this.digest.update(copyOfRange7, 0, this.len_pkh_bytes);
        this.digest.update(decode, 0, this.len_mu_bytes);
        this.digest.doFinal(bArr4, 0, this.len_seedSE_bytes + this.len_k_bytes);
        int i10 = this.len_seedSE_bytes;
        byte[] copyOfRange8 = Arrays.copyOfRange(bArr4, i10, this.len_k_bytes + i10);
        int i11 = ((this.f1252n * 16) + 64) * 2;
        byte[] bArr5 = new byte[i11];
        this.digest.update((byte) -106);
        this.digest.update(bArr4, 0, this.len_seedSE_bytes);
        this.digest.doFinal(bArr5, 0, i11);
        int i12 = (this.f1252n * 16) + 64;
        short[] sArr2 = new short[i12];
        for (int i13 = 0; i13 < i12; i13++) {
            sArr2[i13] = Pack.littleEndianToShort(bArr5, i13 * 2);
        }
        short[] sample_matrix = sample_matrix(sArr2, 0, 8, this.f1252n);
        int i14 = this.f1252n;
        short[] sample_matrix2 = sample_matrix(sArr2, i14 * 8, 8, i14);
        short[] genMatrix = this.gen.genMatrix(copyOfRange4);
        int i15 = this.f1252n;
        short[] matrix_add = matrix_add(matrix_mul(sample_matrix, 8, i15, genMatrix, i15, i15), sample_matrix2, 8, this.f1252n);
        short[] sample_matrix3 = sample_matrix(sArr2, this.f1252n * 16, 8, 8);
        short[] unpack3 = unpack(copyOfRange5, this.f1252n, 8);
        int i16 = this.f1252n;
        byte[] ctselect = ctselect(copyOfRange8, copyOfRange3, ctverify(unpack, unpack2, matrix_add, matrix_add(matrix_add(matrix_mul(sample_matrix, 8, i16, unpack3, i16, 8), sample_matrix3, 8, 8), encode(decode), 8, 8)));
        this.digest.update(copyOfRange, 0, copyOfRange.length);
        this.digest.update(copyOfRange2, 0, copyOfRange2.length);
        this.digest.update(ctselect, 0, ctselect.length);
        this.digest.doFinal(bArr, 0, this.len_ss_bytes);
    }

    public void kem_enc(byte[] bArr, byte[] bArr2, byte[] bArr3, SecureRandom secureRandom) {
        byte[] copyOfRange = Arrays.copyOfRange(bArr3, 0, 16);
        byte[] copyOfRange2 = Arrays.copyOfRange(bArr3, 16, this.len_pk_bytes);
        byte[] bArr4 = new byte[this.len_mu_bytes];
        secureRandom.nextBytes(bArr4);
        byte[] bArr5 = new byte[this.len_pkh_bytes];
        this.digest.update(bArr3, 0, this.len_pk_bytes);
        this.digest.doFinal(bArr5, 0, this.len_pkh_bytes);
        byte[] bArr6 = new byte[this.len_seedSE + this.len_k];
        this.digest.update(bArr5, 0, this.len_pkh_bytes);
        this.digest.update(bArr4, 0, this.len_mu_bytes);
        this.digest.doFinal(bArr6, 0, this.len_seedSE_bytes + this.len_k_bytes);
        byte[] copyOfRange3 = Arrays.copyOfRange(bArr6, 0, this.len_seedSE_bytes);
        int i = this.len_seedSE_bytes;
        byte[] copyOfRange4 = Arrays.copyOfRange(bArr6, i, this.len_k_bytes + i);
        int i2 = ((this.f1252n * 16) + 64) * 2;
        byte[] bArr7 = new byte[i2];
        this.digest.update((byte) -106);
        this.digest.update(copyOfRange3, 0, copyOfRange3.length);
        this.digest.doFinal(bArr7, 0, i2);
        int i3 = i2 / 2;
        short[] sArr = new short[i3];
        for (int i4 = 0; i4 < i3; i4++) {
            sArr[i4] = Pack.littleEndianToShort(bArr7, i4 * 2);
        }
        short[] sample_matrix = sample_matrix(sArr, 0, 8, this.f1252n);
        int i5 = this.f1252n;
        short[] sample_matrix2 = sample_matrix(sArr, i5 * 8, 8, i5);
        short[] genMatrix = this.gen.genMatrix(copyOfRange);
        int i6 = this.f1252n;
        byte[] pack = pack(matrix_add(matrix_mul(sample_matrix, 8, i6, genMatrix, i6, i6), sample_matrix2, 8, this.f1252n));
        short[] sample_matrix3 = sample_matrix(sArr, this.f1252n * 16, 8, 8);
        short[] unpack = unpack(copyOfRange2, this.f1252n, 8);
        int i7 = this.f1252n;
        byte[] pack2 = pack(matrix_add(matrix_add(matrix_mul(sample_matrix, 8, i7, unpack, i7, 8), sample_matrix3, 8, 8), encode(bArr4), 8, 8));
        System.arraycopy(Arrays.concatenate(pack, pack2), 0, bArr, 0, this.len_ct_bytes);
        this.digest.update(pack, 0, pack.length);
        this.digest.update(pack2, 0, pack2.length);
        this.digest.update(copyOfRange4, 0, this.len_k_bytes);
        this.digest.doFinal(bArr2, 0, this.len_s_bytes);
    }

    public void kem_keypair(byte[] bArr, byte[] bArr2, SecureRandom secureRandom) {
        byte[] bArr3 = new byte[this.len_s_bytes + this.len_seedSE_bytes + 16];
        secureRandom.nextBytes(bArr3);
        byte[] copyOfRange = Arrays.copyOfRange(bArr3, 0, this.len_s_bytes);
        int i = this.len_s_bytes;
        byte[] copyOfRange2 = Arrays.copyOfRange(bArr3, i, this.len_seedSE_bytes + i);
        int i2 = this.len_s_bytes;
        int i3 = this.len_seedSE_bytes;
        byte[] copyOfRange3 = Arrays.copyOfRange(bArr3, i2 + i3, i2 + i3 + 16);
        byte[] bArr4 = new byte[16];
        this.digest.update(copyOfRange3, 0, copyOfRange3.length);
        this.digest.doFinal(bArr4, 0, 16);
        short[] genMatrix = this.gen.genMatrix(bArr4);
        int i4 = this.f1252n * 32;
        byte[] bArr5 = new byte[i4];
        this.digest.update((byte) 95);
        this.digest.update(copyOfRange2, 0, copyOfRange2.length);
        this.digest.doFinal(bArr5, 0, i4);
        int i5 = this.f1252n * 16;
        short[] sArr = new short[i5];
        for (int i6 = 0; i6 < i5; i6++) {
            sArr[i6] = Pack.littleEndianToShort(bArr5, i6 * 2);
        }
        short[] sample_matrix = sample_matrix(sArr, 0, 8, this.f1252n);
        short[] matrix_transpose = matrix_transpose(sample_matrix, 8, this.f1252n);
        int i7 = this.f1252n;
        short[] sample_matrix2 = sample_matrix(sArr, i7 * 8, i7, 8);
        int i8 = this.f1252n;
        System.arraycopy(Arrays.concatenate(bArr4, pack(matrix_add(matrix_mul(genMatrix, i8, i8, matrix_transpose, i8, 8), sample_matrix2, this.f1252n, 8))), 0, bArr, 0, this.len_pk_bytes);
        int i9 = this.len_pkh_bytes;
        byte[] bArr6 = new byte[i9];
        this.digest.update(bArr, 0, bArr.length);
        this.digest.doFinal(bArr6, 0, i9);
        System.arraycopy(Arrays.concatenate(copyOfRange, bArr), 0, bArr2, 0, this.len_s_bytes + this.len_pk_bytes);
        for (int i10 = 0; i10 < 8; i10++) {
            int i11 = 0;
            while (true) {
                int i12 = this.f1252n;
                if (i11 < i12) {
                    System.arraycopy(Pack.shortToLittleEndian(sample_matrix[(i12 * i10) + i11]), 0, bArr2, this.len_s_bytes + this.len_pk_bytes + (this.f1252n * i10 * 2) + (i11 * 2), 2);
                    i11++;
                }
            }
        }
        int i13 = this.len_sk_bytes;
        int i14 = this.len_pkh_bytes;
        System.arraycopy(bArr6, 0, bArr2, i13 - i14, i14);
    }
}