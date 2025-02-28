package org.bouncycastle.crypto.digests;

import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/digests/Haraka256Digest.class */
public class Haraka256Digest extends HarakaBase {

    /* renamed from: RC */
    private static final byte[][] f164RC = {new byte[]{6, -124, 112, 76, -26, 32, -64, 10, -78, -59, -2, -16, 117, -127, 123, -99}, new byte[]{-117, 102, -76, -31, -120, -13, -96, 107, 100, 15, 107, -92, 47, 8, -9, 23}, new byte[]{52, 2, -34, 45, 83, -14, -124, -104, -49, 2, -99, 96, -97, 2, -111, 20}, new byte[]{14, -42, -22, -26, 46, 123, 79, 8, -69, -13, -68, -81, -3, 91, 79, 121}, new byte[]{-53, -49, -80, -53, 72, 114, 68, -117, 121, -18, -51, 28, -66, 57, 112, 68}, new byte[]{126, -22, -51, -18, 110, -112, 50, -73, -115, 83, 53, -19, 43, -118, 5, 123}, new byte[]{103, -62, -113, 67, 94, 46, 124, -48, -30, 65, 39, 97, -38, 79, -17, 27}, new byte[]{41, 36, -39, -80, -81, -54, -52, 7, 103, 95, -3, -30, 31, -57, 11, 59}, new byte[]{-85, 77, 99, -15, -26, -122, Byte.MAX_VALUE, -23, -20, -37, -113, -54, -71, -44, 101, -18}, new byte[]{28, 48, -65, -124, -44, -73, -51, 100, 91, 42, 64, 79, -83, 3, 126, 51}, new byte[]{-78, -52, 11, -71, -108, 23, 35, -65, 105, 2, -117, 46, -115, -10, -104, 0}, new byte[]{-6, 4, 120, -90, -34, 111, 85, 114, 74, -86, -98, -56, 92, -99, 45, -118}, new byte[]{-33, -76, -97, 43, 107, 119, 42, 18, 14, -6, 79, 46, 41, 18, -97, -44}, new byte[]{30, -95, 3, 68, -12, 73, -94, 54, 50, -42, 17, -82, -69, 106, 18, -18}, new byte[]{-81, 4, 73, -120, 75, 5, 0, -124, 95, -106, 0, -55, -100, -88, -20, -90}, new byte[]{33, 2, 94, -40, -99, 25, -100, 79, 120, -94, -57, -29, 39, -27, -109, -20}, new byte[]{-65, 58, -86, -8, -89, 89, -55, -73, -71, 40, 46, -51, -126, -44, 1, 115}, new byte[]{98, 96, 112, 13, 97, -122, -80, 23, 55, -14, -17, -39, 16, 48, 125, 107}, new byte[]{90, -54, 69, -62, 33, 48, 4, 67, -127, -62, -111, 83, -10, -4, -102, -58}, new byte[]{-110, 35, -105, 60, 34, 107, 104, -69, 44, -81, -110, -24, 54, -47, -108, 58}};
    private final byte[] buffer;
    private int off;

    private void mix256(byte[][] bArr, byte[][] bArr2) {
        System.arraycopy(bArr[0], 0, bArr2[0], 0, 4);
        System.arraycopy(bArr[1], 0, bArr2[0], 4, 4);
        System.arraycopy(bArr[0], 4, bArr2[0], 8, 4);
        System.arraycopy(bArr[1], 4, bArr2[0], 12, 4);
        System.arraycopy(bArr[0], 8, bArr2[1], 0, 4);
        System.arraycopy(bArr[1], 8, bArr2[1], 4, 4);
        System.arraycopy(bArr[0], 12, bArr2[1], 8, 4);
        System.arraycopy(bArr[1], 12, bArr2[1], 12, 4);
    }

    private int haraka256256(byte[] bArr, byte[] bArr2, int i) {
        byte[][] bArr3 = new byte[2][16];
        System.arraycopy(bArr, 0, r0[0], 0, 16);
        System.arraycopy(bArr, 16, r0[1], 0, 16);
        byte[][] bArr4 = {aesEnc(bArr4[0], f164RC[0]), aesEnc(bArr4[1], f164RC[1])};
        bArr4[0] = aesEnc(bArr4[0], f164RC[2]);
        bArr4[1] = aesEnc(bArr4[1], f164RC[3]);
        mix256(bArr4, bArr3);
        bArr4[0] = aesEnc(bArr3[0], f164RC[4]);
        bArr4[1] = aesEnc(bArr3[1], f164RC[5]);
        bArr4[0] = aesEnc(bArr4[0], f164RC[6]);
        bArr4[1] = aesEnc(bArr4[1], f164RC[7]);
        mix256(bArr4, bArr3);
        bArr4[0] = aesEnc(bArr3[0], f164RC[8]);
        bArr4[1] = aesEnc(bArr3[1], f164RC[9]);
        bArr4[0] = aesEnc(bArr4[0], f164RC[10]);
        bArr4[1] = aesEnc(bArr4[1], f164RC[11]);
        mix256(bArr4, bArr3);
        bArr4[0] = aesEnc(bArr3[0], f164RC[12]);
        bArr4[1] = aesEnc(bArr3[1], f164RC[13]);
        bArr4[0] = aesEnc(bArr4[0], f164RC[14]);
        bArr4[1] = aesEnc(bArr4[1], f164RC[15]);
        mix256(bArr4, bArr3);
        bArr4[0] = aesEnc(bArr3[0], f164RC[16]);
        bArr4[1] = aesEnc(bArr3[1], f164RC[17]);
        bArr4[0] = aesEnc(bArr4[0], f164RC[18]);
        bArr4[1] = aesEnc(bArr4[1], f164RC[19]);
        mix256(bArr4, bArr3);
        bArr4[0] = xor(bArr3[0], bArr, 0);
        bArr4[1] = xor(bArr3[1], bArr, 16);
        System.arraycopy(bArr4[0], 0, bArr2, i, 16);
        System.arraycopy(bArr4[1], 0, bArr2, i + 16, 16);
        return 32;
    }

    public Haraka256Digest() {
        this.buffer = new byte[32];
    }

    public Haraka256Digest(Haraka256Digest haraka256Digest) {
        this.buffer = Arrays.clone(haraka256Digest.buffer);
        this.off = haraka256Digest.off;
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "Haraka-256";
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        if (this.off + 1 > 32) {
            throw new IllegalArgumentException("total input cannot be more than 32 bytes");
        }
        byte[] bArr = this.buffer;
        int i = this.off;
        this.off = i + 1;
        bArr[i] = b;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        if (this.off + i2 > 32) {
            throw new IllegalArgumentException("total input cannot be more than 32 bytes");
        }
        System.arraycopy(bArr, i, this.buffer, this.off, i2);
        this.off += i2;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        if (this.off != 32) {
            throw new IllegalStateException("input must be exactly 32 bytes");
        }
        if (bArr.length - i < 32) {
            throw new IllegalArgumentException("output too short to receive digest");
        }
        int haraka256256 = haraka256256(this.buffer, bArr, i);
        reset();
        return haraka256256;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.off = 0;
        Arrays.clear(this.buffer);
    }
}