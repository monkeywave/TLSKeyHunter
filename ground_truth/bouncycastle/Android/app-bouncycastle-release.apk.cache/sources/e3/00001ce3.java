package org.bouncycastle.crypto.digests;

import java.io.ByteArrayOutputStream;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class XoodyakDigest implements Digest {
    private int Rabsorb;
    private MODE mode;
    private int phase;
    private final int f_bPrime = 48;
    private final int Rhash = 16;
    private final int PhaseDown = 1;
    private final int PhaseUp = 2;
    private final int MAXROUNDS = 12;
    private final int TAGLEN = 16;

    /* renamed from: RC */
    private final int[] f549RC = {88, 56, 960, 208, 288, 20, 96, 44, 896, 240, 416, 18};
    private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
    private byte[] state = new byte[48];

    /* JADX INFO: Access modifiers changed from: package-private */
    /* loaded from: classes2.dex */
    public enum MODE {
        ModeHash,
        ModeKeyed
    }

    public XoodyakDigest() {
        reset();
    }

    /* renamed from: Up */
    private void m86Up(byte[] bArr, int i, int i2, int i3) {
        XoodyakDigest xoodyakDigest = this;
        if (xoodyakDigest.mode != MODE.ModeHash) {
            byte[] bArr2 = xoodyakDigest.state;
            bArr2[47] = (byte) (bArr2[47] ^ i3);
        }
        int littleEndianToInt = Pack.littleEndianToInt(xoodyakDigest.state, 0);
        int littleEndianToInt2 = Pack.littleEndianToInt(xoodyakDigest.state, 4);
        int littleEndianToInt3 = Pack.littleEndianToInt(xoodyakDigest.state, 8);
        int i4 = 12;
        int littleEndianToInt4 = Pack.littleEndianToInt(xoodyakDigest.state, 12);
        int littleEndianToInt5 = Pack.littleEndianToInt(xoodyakDigest.state, 16);
        int littleEndianToInt6 = Pack.littleEndianToInt(xoodyakDigest.state, 20);
        int littleEndianToInt7 = Pack.littleEndianToInt(xoodyakDigest.state, 24);
        int littleEndianToInt8 = Pack.littleEndianToInt(xoodyakDigest.state, 28);
        int littleEndianToInt9 = Pack.littleEndianToInt(xoodyakDigest.state, 32);
        int littleEndianToInt10 = Pack.littleEndianToInt(xoodyakDigest.state, 36);
        int littleEndianToInt11 = Pack.littleEndianToInt(xoodyakDigest.state, 40);
        int littleEndianToInt12 = Pack.littleEndianToInt(xoodyakDigest.state, 44);
        int i5 = 0;
        while (i5 < i4) {
            int i6 = (littleEndianToInt ^ littleEndianToInt5) ^ littleEndianToInt9;
            int i7 = (littleEndianToInt2 ^ littleEndianToInt6) ^ littleEndianToInt10;
            int i8 = i5;
            int i9 = (littleEndianToInt3 ^ littleEndianToInt7) ^ littleEndianToInt11;
            int i10 = (littleEndianToInt4 ^ littleEndianToInt8) ^ littleEndianToInt12;
            int i11 = littleEndianToInt12;
            int rotateLeft = Integers.rotateLeft(i10, 5) ^ Integers.rotateLeft(i10, 14);
            int i12 = littleEndianToInt8;
            int rotateLeft2 = Integers.rotateLeft(i6, 5) ^ Integers.rotateLeft(i6, 14);
            int rotateLeft3 = Integers.rotateLeft(i7, 5) ^ Integers.rotateLeft(i7, 14);
            int rotateLeft4 = Integers.rotateLeft(i9, 14) ^ Integers.rotateLeft(i9, 5);
            int i13 = littleEndianToInt ^ rotateLeft;
            int i14 = littleEndianToInt5 ^ rotateLeft;
            int i15 = littleEndianToInt2 ^ rotateLeft2;
            int i16 = littleEndianToInt6 ^ rotateLeft2;
            int i17 = rotateLeft2 ^ littleEndianToInt10;
            int i18 = littleEndianToInt3 ^ rotateLeft3;
            int i19 = littleEndianToInt7 ^ rotateLeft3;
            int i20 = rotateLeft3 ^ littleEndianToInt11;
            int i21 = littleEndianToInt4 ^ rotateLeft4;
            int i22 = i12 ^ rotateLeft4;
            int rotateLeft5 = Integers.rotateLeft(rotateLeft ^ littleEndianToInt9, 11);
            int rotateLeft6 = Integers.rotateLeft(i17, 11);
            int rotateLeft7 = Integers.rotateLeft(i20, 11);
            int rotateLeft8 = Integers.rotateLeft(i11 ^ rotateLeft4, 11);
            int i23 = i13 ^ this.f549RC[i8];
            int i24 = ((~i22) & rotateLeft5) ^ i23;
            int i25 = ((~i14) & rotateLeft6) ^ i15;
            int i26 = ((~i16) & rotateLeft7) ^ i18;
            int i27 = ((~i19) & rotateLeft8) ^ i21;
            int i28 = ((~rotateLeft7) & i18) ^ i16;
            int i29 = rotateLeft5 ^ ((~i23) & i22);
            int i30 = rotateLeft7 ^ ((~i18) & i16);
            littleEndianToInt5 = Integers.rotateLeft(((~rotateLeft5) & i23) ^ i22, 1);
            littleEndianToInt6 = Integers.rotateLeft(((~rotateLeft6) & i15) ^ i14, 1);
            littleEndianToInt7 = Integers.rotateLeft(i28, 1);
            littleEndianToInt8 = Integers.rotateLeft(((~rotateLeft8) & i21) ^ i19, 1);
            littleEndianToInt9 = Integers.rotateLeft(i30, 8);
            littleEndianToInt10 = Integers.rotateLeft(rotateLeft8 ^ ((~i21) & i19), 8);
            littleEndianToInt11 = Integers.rotateLeft(i29, 8);
            littleEndianToInt12 = Integers.rotateLeft(((~i15) & i14) ^ rotateLeft6, 8);
            i5 = i8 + 1;
            littleEndianToInt = i24;
            littleEndianToInt4 = i27;
            littleEndianToInt2 = i25;
            littleEndianToInt3 = i26;
            i4 = 12;
            xoodyakDigest = this;
        }
        Pack.intToLittleEndian(littleEndianToInt, xoodyakDigest.state, 0);
        Pack.intToLittleEndian(littleEndianToInt2, xoodyakDigest.state, 4);
        Pack.intToLittleEndian(littleEndianToInt3, xoodyakDigest.state, 8);
        Pack.intToLittleEndian(littleEndianToInt4, xoodyakDigest.state, 12);
        Pack.intToLittleEndian(littleEndianToInt5, xoodyakDigest.state, 16);
        Pack.intToLittleEndian(littleEndianToInt6, xoodyakDigest.state, 20);
        Pack.intToLittleEndian(littleEndianToInt7, xoodyakDigest.state, 24);
        Pack.intToLittleEndian(littleEndianToInt8, xoodyakDigest.state, 28);
        Pack.intToLittleEndian(littleEndianToInt9, xoodyakDigest.state, 32);
        Pack.intToLittleEndian(littleEndianToInt10, xoodyakDigest.state, 36);
        Pack.intToLittleEndian(littleEndianToInt11, xoodyakDigest.state, 40);
        Pack.intToLittleEndian(littleEndianToInt12, xoodyakDigest.state, 44);
        xoodyakDigest.phase = 2;
        if (bArr != null) {
            System.arraycopy(xoodyakDigest.state, 0, bArr, i, i2);
        }
    }

    void Down(byte[] bArr, int i, int i2, int i3) {
        int i4 = 0;
        while (i4 < i2) {
            byte[] bArr2 = this.state;
            bArr2[i4] = (byte) (bArr[i] ^ bArr2[i4]);
            i4++;
            i++;
        }
        byte[] bArr3 = this.state;
        bArr3[i2] = (byte) (bArr3[i2] ^ 1);
        byte b = bArr3[47];
        if (this.mode == MODE.ModeHash) {
            i3 &= 1;
        }
        bArr3[47] = (byte) (b ^ i3);
        this.phase = 1;
    }

    @Override // org.bouncycastle.crypto.Digest
    public int doFinal(byte[] bArr, int i) {
        if (i + 32 > bArr.length) {
            throw new OutputLengthException("output buffer is too short");
        }
        byte[] byteArray = this.buffer.toByteArray();
        int size = this.buffer.size();
        int i2 = 3;
        int i3 = 0;
        while (true) {
            if (this.phase != 2) {
                m86Up(null, 0, 0, 0);
            }
            int min = Math.min(size, this.Rabsorb);
            Down(byteArray, i3, min, i2);
            i3 += min;
            size -= min;
            if (size == 0) {
                m86Up(bArr, i, 16, 64);
                Down(null, 0, 0, 0);
                m86Up(bArr, i + 16, 16, 0);
                reset();
                return 32;
            }
            i2 = 0;
        }
    }

    @Override // org.bouncycastle.crypto.Digest
    public String getAlgorithmName() {
        return "Xoodyak Hash";
    }

    @Override // org.bouncycastle.crypto.Digest
    public int getDigestSize() {
        return 32;
    }

    @Override // org.bouncycastle.crypto.Digest
    public void reset() {
        Arrays.fill(this.state, (byte) 0);
        this.phase = 2;
        this.mode = MODE.ModeHash;
        this.Rabsorb = 16;
        this.buffer.reset();
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