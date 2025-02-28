package org.bouncycastle.crypto.generators;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/generators/PKCS12ParametersGenerator.class */
public class PKCS12ParametersGenerator extends PBEParametersGenerator {
    public static final int KEY_MATERIAL = 1;
    public static final int IV_MATERIAL = 2;
    public static final int MAC_MATERIAL = 3;
    private Digest digest;

    /* renamed from: u */
    private int f411u;

    /* renamed from: v */
    private int f412v;

    public PKCS12ParametersGenerator(Digest digest) {
        this.digest = digest;
        if (!(digest instanceof ExtendedDigest)) {
            throw new IllegalArgumentException("Digest " + digest.getAlgorithmName() + " unsupported");
        }
        this.f411u = digest.getDigestSize();
        this.f412v = ((ExtendedDigest) digest).getByteLength();
    }

    private void adjust(byte[] bArr, int i, byte[] bArr2) {
        int i2 = (bArr2[bArr2.length - 1] & 255) + (bArr[(i + bArr2.length) - 1] & 255) + 1;
        bArr[(i + bArr2.length) - 1] = (byte) i2;
        int i3 = i2 >>> 8;
        for (int length = bArr2.length - 2; length >= 0; length--) {
            int i4 = i3 + (bArr2[length] & 255) + (bArr[i + length] & 255);
            bArr[i + length] = (byte) i4;
            i3 = i4 >>> 8;
        }
    }

    private byte[] generateDerivedKey(int i, int i2) {
        byte[] bArr;
        byte[] bArr2;
        byte[] bArr3 = new byte[this.f412v];
        byte[] bArr4 = new byte[i2];
        for (int i3 = 0; i3 != bArr3.length; i3++) {
            bArr3[i3] = (byte) i;
        }
        if (this.salt == null || this.salt.length == 0) {
            bArr = new byte[0];
        } else {
            bArr = new byte[this.f412v * (((this.salt.length + this.f412v) - 1) / this.f412v)];
            for (int i4 = 0; i4 != bArr.length; i4++) {
                bArr[i4] = this.salt[i4 % this.salt.length];
            }
        }
        if (this.password == null || this.password.length == 0) {
            bArr2 = new byte[0];
        } else {
            bArr2 = new byte[this.f412v * (((this.password.length + this.f412v) - 1) / this.f412v)];
            for (int i5 = 0; i5 != bArr2.length; i5++) {
                bArr2[i5] = this.password[i5 % this.password.length];
            }
        }
        byte[] bArr5 = new byte[bArr.length + bArr2.length];
        System.arraycopy(bArr, 0, bArr5, 0, bArr.length);
        System.arraycopy(bArr2, 0, bArr5, bArr.length, bArr2.length);
        byte[] bArr6 = new byte[this.f412v];
        int i6 = ((i2 + this.f411u) - 1) / this.f411u;
        byte[] bArr7 = new byte[this.f411u];
        for (int i7 = 1; i7 <= i6; i7++) {
            this.digest.update(bArr3, 0, bArr3.length);
            this.digest.update(bArr5, 0, bArr5.length);
            this.digest.doFinal(bArr7, 0);
            for (int i8 = 1; i8 < this.iterationCount; i8++) {
                this.digest.update(bArr7, 0, bArr7.length);
                this.digest.doFinal(bArr7, 0);
            }
            for (int i9 = 0; i9 != bArr6.length; i9++) {
                bArr6[i9] = bArr7[i9 % bArr7.length];
            }
            for (int i10 = 0; i10 != bArr5.length / this.f412v; i10++) {
                adjust(bArr5, i10 * this.f412v, bArr6);
            }
            if (i7 == i6) {
                System.arraycopy(bArr7, 0, bArr4, (i7 - 1) * this.f411u, bArr4.length - ((i7 - 1) * this.f411u));
            } else {
                System.arraycopy(bArr7, 0, bArr4, (i7 - 1) * this.f411u, bArr7.length);
            }
        }
        return bArr4;
    }

    @Override // org.bouncycastle.crypto.PBEParametersGenerator
    public CipherParameters generateDerivedParameters(int i) {
        int i2 = i / 8;
        return new KeyParameter(generateDerivedKey(1, i2), 0, i2);
    }

    @Override // org.bouncycastle.crypto.PBEParametersGenerator
    public CipherParameters generateDerivedParameters(int i, int i2) {
        int i3 = i / 8;
        int i4 = i2 / 8;
        byte[] generateDerivedKey = generateDerivedKey(1, i3);
        return new ParametersWithIV(new KeyParameter(generateDerivedKey, 0, i3), generateDerivedKey(2, i4), 0, i4);
    }

    @Override // org.bouncycastle.crypto.PBEParametersGenerator
    public CipherParameters generateDerivedMacParameters(int i) {
        int i2 = i / 8;
        return new KeyParameter(generateDerivedKey(3, i2), 0, i2);
    }
}