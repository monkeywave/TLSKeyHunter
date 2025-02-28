package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;
import java.lang.reflect.Array;
import kotlin.UByte;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Bytes;

/* loaded from: classes2.dex */
public class PhotonBeetleDigest implements Digest {
    private ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private final int INITIAL_RATE_INBYTES = 16;
    private int RATE_INBYTES = 4;
    private int SQUEEZE_RATE_INBYTES = 16;
    private int STATE_INBYTES = 32;
    private int TAG_INBYTES = 32;
    private int LAST_THREE_BITS_OFFSET = 5;
    private int ROUND = 12;

    /* renamed from: D */
    private int f461D = 8;

    /* renamed from: Dq */
    private int f462Dq = 3;

    /* renamed from: Dr */
    private int f463Dr = 7;
    private int DSquare = 64;

    /* renamed from: S */
    private int f465S = 4;
    private int S_1 = 3;

    /* renamed from: RC */
    private byte[][] f464RC = {new byte[]{1, 3, 7, 14, 13, 11, 6, 12, 9, 2, 5, 10}, new byte[]{0, 2, 6, 15, 12, 10, 7, 13, 8, 3, 4, 11}, new byte[]{2, 0, 4, 13, 14, 8, 5, 15, 10, 1, 6, 9}, new byte[]{6, 4, 0, 9, 10, 12, 1, 11, 14, 5, 2, 13}, new byte[]{14, 12, 8, 1, 2, 4, 9, 3, 6, 13, 10, 5}, new byte[]{15, 13, 9, 0, 3, 5, 8, 2, 7, 12, 11, 4}, new byte[]{13, 15, 11, 2, 1, 7, 10, 0, 5, 14, 9, 6}, new byte[]{9, 11, 15, 6, 5, 3, 14, 4, 1, 10, 13, 2}};
    private byte[][] MixColMatrix = {new byte[]{2, 4, 2, 11, 2, 8, 5, 6}, new byte[]{12, 9, 8, 13, 7, 7, 5, 2}, new byte[]{4, 4, 13, 13, 9, 4, 13, 9}, new byte[]{1, 6, 5, 1, 12, 13, 15, 14}, new byte[]{15, 12, 9, 13, 14, 5, 14, 13}, new byte[]{9, 14, 5, 15, 4, 12, 9, 6}, new byte[]{12, 2, 2, 10, 3, 1, 1, 14}, new byte[]{15, 1, 13, 10, 5, 10, 2, 3}};
    private byte[] sbox = {12, 5, 6, 11, 9, 0, 10, 13, 3, 14, 15, 8, 4, 7, 1, 2};
    private byte[] state = new byte[32];
    private byte[][] state_2d = (byte[][]) Array.newInstance(Byte.TYPE, 8, 8);

    void PHOTON_Permutation() {
        for (int i = 0; i < this.DSquare; i++) {
            this.state_2d[i >>> this.f462Dq][this.f463Dr & i] = (byte) (((this.state[i >> 1] & UByte.MAX_VALUE) >>> ((i & 1) * 4)) & 15);
        }
        for (int i2 = 0; i2 < this.ROUND; i2++) {
            for (int i3 = 0; i3 < this.f461D; i3++) {
                byte[] bArr = this.state_2d[i3];
                bArr[0] = (byte) (bArr[0] ^ this.f464RC[i3][i2]);
            }
            for (int i4 = 0; i4 < this.f461D; i4++) {
                for (int i5 = 0; i5 < this.f461D; i5++) {
                    byte[] bArr2 = this.state_2d[i4];
                    bArr2[i5] = this.sbox[bArr2[i5]];
                }
            }
            int i6 = 1;
            while (true) {
                int i7 = this.f461D;
                if (i6 >= i7) {
                    break;
                }
                System.arraycopy(this.state_2d[i6], 0, this.state, 0, i7);
                System.arraycopy(this.state, i6, this.state_2d[i6], 0, this.f461D - i6);
                System.arraycopy(this.state, 0, this.state_2d[i6], this.f461D - i6, i6);
                i6++;
            }
            for (int i8 = 0; i8 < this.f461D; i8++) {
                for (int i9 = 0; i9 < this.f461D; i9++) {
                    int i10 = 0;
                    for (int i11 = 0; i11 < this.f461D; i11++) {
                        byte b = this.MixColMatrix[i9][i11];
                        byte b2 = this.state_2d[i11][i8];
                        i10 = (((i10 ^ ((b2 & 1) * b)) ^ ((b2 & 2) * b)) ^ ((b2 & 4) * b)) ^ (b * (b2 & 8));
                    }
                    int i12 = i10 >>> 4;
                    int i13 = (i12 << 1) ^ ((i10 & 15) ^ i12);
                    int i14 = i13 >>> 4;
                    this.state[i9] = (byte) (((i13 & 15) ^ i14) ^ (i14 << 1));
                }
                for (int i15 = 0; i15 < this.f461D; i15++) {
                    this.state_2d[i15][i8] = this.state[i15];
                }
            }
        }
        for (int i16 = 0; i16 < this.DSquare; i16 += 2) {
            byte[][] bArr3 = this.state_2d;
            int i17 = this.f462Dq;
            byte[] bArr4 = bArr3[i16 >>> i17];
            int i18 = this.f463Dr;
            this.state[i16 >>> 1] = (byte) (((bArr3[i16 >>> i17][(i16 + 1) & i18] & 15) << 4) | (bArr4[i16 & i18] & 15));
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        if (i + 32 <= bArr.length) {
            byte[] byteArray = this.buffer.toByteArray();
            int length = byteArray.length;
            if (length == 0) {
                byte[] bArr2 = this.state;
                int i2 = this.STATE_INBYTES - 1;
                bArr2[i2] = (byte) ((1 << this.LAST_THREE_BITS_OFFSET) ^ bArr2[i2]);
            } else {
                byte[] bArr3 = this.state;
                if (length <= 16) {
                    System.arraycopy(byteArray, 0, bArr3, 0, length);
                    if (length < 16) {
                        byte[] bArr4 = this.state;
                        bArr4[length] = (byte) (bArr4[length] ^ 1);
                    }
                    byte[] bArr5 = this.state;
                    int i3 = this.STATE_INBYTES - 1;
                    bArr5[i3] = (byte) (((length >= 16 ? 2 : 1) << this.LAST_THREE_BITS_OFFSET) ^ bArr5[i3]);
                } else {
                    System.arraycopy(byteArray, 0, bArr3, 0, 16);
                    int i4 = length - 16;
                    int i5 = this.RATE_INBYTES;
                    int i6 = ((i4 + i5) - 1) / i5;
                    int i7 = 0;
                    while (true) {
                        int i8 = i6 - 1;
                        PHOTON_Permutation();
                        if (i7 >= i8) {
                            break;
                        }
                        int i9 = this.RATE_INBYTES;
                        Bytes.xorTo(i9, byteArray, (i7 * i9) + 16, this.state, 0);
                        i7++;
                    }
                    int i10 = this.RATE_INBYTES;
                    int i11 = i4 - (i7 * i10);
                    Bytes.xorTo(i11, byteArray, (i7 * i10) + 16, this.state, 0);
                    int i12 = this.RATE_INBYTES;
                    if (i11 < i12) {
                        byte[] bArr6 = this.state;
                        bArr6[i11] = (byte) (bArr6[i11] ^ 1);
                    }
                    byte[] bArr7 = this.state;
                    int i13 = this.STATE_INBYTES - 1;
                    bArr7[i13] = (byte) (((i4 % i12 != 0 ? 2 : 1) << this.LAST_THREE_BITS_OFFSET) ^ bArr7[i13]);
                }
            }
            PHOTON_Permutation();
            System.arraycopy(this.state, 0, bArr, i, this.SQUEEZE_RATE_INBYTES);
            PHOTON_Permutation();
            byte[] bArr8 = this.state;
            int i14 = this.SQUEEZE_RATE_INBYTES;
            System.arraycopy(bArr8, 0, bArr, i + i14, this.TAG_INBYTES - i14);
            reset();
            return this.TAG_INBYTES;
        }
        throw new OutputLengthException("output buffer is too short");
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "Photon-Beetle Hash";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return this.TAG_INBYTES;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        this.buffer.reset();
        Arrays.fill(this.state, (byte) 0);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte b) {
        this.buffer.write(b);
    }

    @Override // org.bouncycastle.crypto.Digest
    public void update(byte[] bArr, int i, int i2) {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        this.buffer.write(bArr, i, i2);
    }
}