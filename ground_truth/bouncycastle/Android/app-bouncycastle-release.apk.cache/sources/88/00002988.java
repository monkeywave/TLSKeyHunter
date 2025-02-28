package org.bouncycastle.pqc.crypto.falcon;

import java.security.SecureRandom;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
class FalconNIST {
    int CRYPTO_BYTES;
    private int CRYPTO_PUBLICKEYBYTES;
    private int CRYPTO_SECRETKEYBYTES;
    int LOGN;

    /* renamed from: N */
    private int f1233N;
    int NONCELEN;
    private FalconCodec codec = new FalconCodec();
    private SecureRandom rand;

    /* JADX INFO: Access modifiers changed from: package-private */
    public FalconNIST(int i, int i2, SecureRandom secureRandom) {
        int i3;
        int i4;
        this.rand = secureRandom;
        this.LOGN = i;
        this.NONCELEN = i2;
        int i5 = 1 << i;
        this.f1233N = i5;
        this.CRYPTO_PUBLICKEYBYTES = ((i5 * 14) / 8) + 1;
        if (i == 10) {
            this.CRYPTO_SECRETKEYBYTES = 2305;
            this.CRYPTO_BYTES = 1330;
            return;
        }
        if (i == 9 || i == 8) {
            i3 = i5 * 12;
        } else if (i != 7 && i != 6) {
            i4 = i5 * 2;
            this.CRYPTO_SECRETKEYBYTES = i4 + 1 + i5;
            this.CRYPTO_BYTES = 690;
        } else {
            i3 = i5 * 14;
        }
        i4 = i3 / 8;
        this.CRYPTO_SECRETKEYBYTES = i4 + 1 + i5;
        this.CRYPTO_BYTES = 690;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[] crypto_sign(boolean z, byte[] bArr, byte[] bArr2, int i, int i2, byte[] bArr3, int i3) {
        int i4;
        int i5;
        int comp_encode;
        int i6 = this.f1233N;
        byte[] bArr4 = new byte[i6];
        byte[] bArr5 = new byte[i6];
        byte[] bArr6 = new byte[i6];
        byte[] bArr7 = new byte[i6];
        short[] sArr = new short[i6];
        short[] sArr2 = new short[i6];
        byte[] bArr8 = new byte[48];
        byte[] bArr9 = new byte[this.NONCELEN];
        SHAKE256 shake256 = new SHAKE256();
        FalconSign falconSign = new FalconSign();
        FalconVrfy falconVrfy = new FalconVrfy();
        FalconCommon falconCommon = new FalconCommon();
        FalconCodec falconCodec = this.codec;
        int trim_i8_decode = falconCodec.trim_i8_decode(bArr4, 0, this.LOGN, falconCodec.max_fg_bits[this.LOGN], bArr3, i3, this.CRYPTO_SECRETKEYBYTES);
        if (trim_i8_decode != 0) {
            FalconCodec falconCodec2 = this.codec;
            int trim_i8_decode2 = falconCodec2.trim_i8_decode(bArr5, 0, this.LOGN, falconCodec2.max_fg_bits[this.LOGN], bArr3, i3 + trim_i8_decode, this.CRYPTO_SECRETKEYBYTES - trim_i8_decode);
            if (trim_i8_decode2 != 0) {
                int i7 = trim_i8_decode + trim_i8_decode2;
                FalconCodec falconCodec3 = this.codec;
                int trim_i8_decode3 = falconCodec3.trim_i8_decode(bArr6, 0, this.LOGN, falconCodec3.max_FG_bits[this.LOGN], bArr3, i3 + i7, this.CRYPTO_SECRETKEYBYTES - i7);
                if (trim_i8_decode3 != 0) {
                    if (i7 + trim_i8_decode3 == this.CRYPTO_SECRETKEYBYTES - 1) {
                        if (falconVrfy.complete_private(bArr7, 0, bArr4, 0, bArr5, 0, bArr6, 0, this.LOGN, new short[this.f1233N * 2], 0)) {
                            this.rand.nextBytes(bArr9);
                            shake256.inner_shake256_init();
                            shake256.inner_shake256_inject(bArr9, 0, this.NONCELEN);
                            shake256.inner_shake256_inject(bArr2, i, i2);
                            shake256.i_shake256_flip();
                            falconCommon.hash_to_point_vartime(shake256, sArr2, 0, this.LOGN);
                            this.rand.nextBytes(bArr8);
                            shake256.inner_shake256_init();
                            shake256.inner_shake256_inject(bArr8, 0, 48);
                            shake256.i_shake256_flip();
                            falconSign.sign_dyn(sArr, 0, shake256, bArr4, 0, bArr5, 0, bArr6, 0, bArr7, 0, sArr2, 0, this.LOGN, new FalconFPR[this.f1233N * 10], 0);
                            int i8 = (this.CRYPTO_BYTES - 2) - this.NONCELEN;
                            byte[] bArr10 = new byte[i8];
                            if (z) {
                                int i9 = this.LOGN;
                                i4 = 0;
                                bArr10[0] = (byte) (i9 + 32);
                                i5 = 1;
                                int comp_encode2 = this.codec.comp_encode(bArr10, 1, i8 - 1, sArr, 0, i9);
                                if (comp_encode2 == 0) {
                                    throw new IllegalStateException("signature failed to generate");
                                }
                                comp_encode = comp_encode2 + 1;
                            } else {
                                i4 = 0;
                                i5 = 1;
                                comp_encode = this.codec.comp_encode(bArr10, 0, i8, sArr, 0, this.LOGN);
                                if (comp_encode == 0) {
                                    throw new IllegalStateException("signature failed to generate");
                                }
                            }
                            bArr[i4] = (byte) (this.LOGN + 48);
                            System.arraycopy(bArr9, i4, bArr, i5, this.NONCELEN);
                            System.arraycopy(bArr10, i4, bArr, this.NONCELEN + i5, comp_encode);
                            return Arrays.copyOfRange(bArr, i4, this.NONCELEN + i5 + comp_encode);
                        }
                        throw new IllegalStateException("complete_private failed");
                    }
                    throw new IllegalStateException("full key not used");
                }
                throw new IllegalArgumentException("F decode failed");
            }
            throw new IllegalStateException("g decode failed");
        }
        throw new IllegalStateException("f decode failed");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public byte[][] crypto_sign_keypair(byte[] bArr, int i, byte[] bArr2, int i2) {
        int i3 = this.f1233N;
        byte[] bArr3 = new byte[i3];
        byte[] bArr4 = new byte[i3];
        byte[] bArr5 = new byte[i3];
        short[] sArr = new short[i3];
        byte[] bArr6 = new byte[48];
        SHAKE256 shake256 = new SHAKE256();
        FalconKeyGen falconKeyGen = new FalconKeyGen();
        this.rand.nextBytes(bArr6);
        shake256.inner_shake256_init();
        shake256.inner_shake256_inject(bArr6, 0, 48);
        shake256.i_shake256_flip();
        falconKeyGen.keygen(shake256, bArr3, 0, bArr4, 0, bArr5, 0, null, 0, sArr, 0, this.LOGN);
        int i4 = this.LOGN;
        bArr2[i2] = (byte) (i4 + 80);
        FalconCodec falconCodec = this.codec;
        int i5 = i2 + 1;
        int trim_i8_encode = falconCodec.trim_i8_encode(bArr2, i5, this.CRYPTO_SECRETKEYBYTES - 1, bArr3, 0, i4, falconCodec.max_fg_bits[this.LOGN]);
        if (trim_i8_encode != 0) {
            int i6 = trim_i8_encode + 1;
            byte[] copyOfRange = Arrays.copyOfRange(bArr2, i5, i6);
            FalconCodec falconCodec2 = this.codec;
            int i7 = i2 + i6;
            int trim_i8_encode2 = falconCodec2.trim_i8_encode(bArr2, i7, this.CRYPTO_SECRETKEYBYTES - i6, bArr4, 0, this.LOGN, falconCodec2.max_fg_bits[this.LOGN]);
            if (trim_i8_encode2 != 0) {
                int i8 = i6 + trim_i8_encode2;
                byte[] copyOfRange2 = Arrays.copyOfRange(bArr2, i7, i8);
                FalconCodec falconCodec3 = this.codec;
                int i9 = i2 + i8;
                int trim_i8_encode3 = falconCodec3.trim_i8_encode(bArr2, i9, this.CRYPTO_SECRETKEYBYTES - i8, bArr5, 0, this.LOGN, falconCodec3.max_FG_bits[this.LOGN]);
                if (trim_i8_encode3 != 0) {
                    int i10 = i8 + trim_i8_encode3;
                    byte[] copyOfRange3 = Arrays.copyOfRange(bArr2, i9, i10);
                    if (i10 == this.CRYPTO_SECRETKEYBYTES) {
                        int i11 = this.LOGN;
                        bArr[i] = (byte) i11;
                        if (this.codec.modq_encode(bArr, i + 1, this.CRYPTO_PUBLICKEYBYTES - 1, sArr, 0, i11) == this.CRYPTO_PUBLICKEYBYTES - 1) {
                            return new byte[][]{Arrays.copyOfRange(bArr, 1, bArr.length), copyOfRange, copyOfRange2, copyOfRange3};
                        }
                        throw new IllegalStateException("public key encoding failed");
                    }
                    throw new IllegalStateException("secret key encoding failed");
                }
                throw new IllegalStateException("F encode failed");
            }
            throw new IllegalStateException("g encode failed");
        }
        throw new IllegalStateException("f encode failed");
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    /* JADX WARN: Code restructure failed: missing block: B:12:0x006e, code lost:
        if (r19.codec.comp_decode(r4, 0, r14, r21, 1, r9) != r9) goto L16;
     */
    /*
        Code decompiled incorrectly, please refer to instructions dump.
        To view partially-correct code enable 'Show inconsistent code' option in preferences
    */
    public int crypto_sign_open(boolean r20, byte[] r21, byte[] r22, byte[] r23, byte[] r24, int r25) {
        /*
            Method dump skipped, instructions count: 191
            To view this dump change 'Code comments level' option to 'DEBUG'
        */
        throw new UnsupportedOperationException("Method not decompiled: org.bouncycastle.pqc.crypto.falcon.FalconNIST.crypto_sign_open(boolean, byte[], byte[], byte[], byte[], int):int");
    }
}