package org.bouncycastle.crypto.macs;

import kotlin.UByte;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/* loaded from: classes2.dex */
public class VMPCMac implements Mac {

    /* renamed from: T */
    private byte[] f763T;

    /* renamed from: g */
    private byte f764g;
    private byte[] workingIV;
    private byte[] workingKey;

    /* renamed from: x1 */
    private byte f767x1;

    /* renamed from: x2 */
    private byte f768x2;

    /* renamed from: x3 */
    private byte f769x3;

    /* renamed from: x4 */
    private byte f770x4;

    /* renamed from: n */
    private byte f765n = 0;

    /* renamed from: P */
    private byte[] f762P = null;

    /* renamed from: s */
    private byte f766s = 0;

    private void initKey(byte[] bArr, byte[] bArr2) {
        this.f766s = (byte) 0;
        this.f762P = new byte[256];
        for (int i = 0; i < 256; i++) {
            this.f762P[i] = (byte) i;
        }
        for (int i2 = 0; i2 < 768; i2++) {
            byte[] bArr3 = this.f762P;
            byte b = this.f766s;
            int i3 = i2 & 255;
            byte b2 = bArr3[i3];
            byte b3 = bArr3[(b + b2 + bArr[i2 % bArr.length]) & 255];
            this.f766s = b3;
            bArr3[i3] = bArr3[b3 & UByte.MAX_VALUE];
            bArr3[b3 & UByte.MAX_VALUE] = b2;
        }
        for (int i4 = 0; i4 < 768; i4++) {
            byte[] bArr4 = this.f762P;
            byte b4 = this.f766s;
            int i5 = i4 & 255;
            byte b5 = bArr4[i5];
            byte b6 = bArr4[(b4 + b5 + bArr2[i4 % bArr2.length]) & 255];
            this.f766s = b6;
            bArr4[i5] = bArr4[b6 & UByte.MAX_VALUE];
            bArr4[b6 & UByte.MAX_VALUE] = b5;
        }
        this.f765n = (byte) 0;
    }

    @Override // org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        for (int i2 = 1; i2 < 25; i2++) {
            byte[] bArr2 = this.f762P;
            byte b = this.f766s;
            byte b2 = this.f765n;
            byte b3 = bArr2[(b + bArr2[b2 & UByte.MAX_VALUE]) & 255];
            this.f766s = b3;
            byte b4 = this.f770x4;
            byte b5 = this.f769x3;
            byte b6 = bArr2[(b4 + b5 + i2) & 255];
            this.f770x4 = b6;
            byte b7 = this.f768x2;
            byte b8 = bArr2[(b5 + b7 + i2) & 255];
            this.f769x3 = b8;
            byte b9 = this.f767x1;
            byte b10 = bArr2[(b7 + b9 + i2) & 255];
            this.f768x2 = b10;
            byte b11 = bArr2[(b9 + b3 + i2) & 255];
            this.f767x1 = b11;
            byte[] bArr3 = this.f763T;
            byte b12 = this.f764g;
            bArr3[b12 & 31] = (byte) (b11 ^ bArr3[b12 & 31]);
            bArr3[(b12 + 1) & 31] = (byte) (b10 ^ bArr3[(b12 + 1) & 31]);
            bArr3[(b12 + 2) & 31] = (byte) (b8 ^ bArr3[(b12 + 2) & 31]);
            bArr3[(b12 + 3) & 31] = (byte) (b6 ^ bArr3[(b12 + 3) & 31]);
            this.f764g = (byte) ((b12 + 4) & 31);
            byte b13 = bArr2[b2 & UByte.MAX_VALUE];
            bArr2[b2 & UByte.MAX_VALUE] = bArr2[b3 & UByte.MAX_VALUE];
            bArr2[b3 & UByte.MAX_VALUE] = b13;
            this.f765n = (byte) ((b2 + 1) & 255);
        }
        for (int i3 = 0; i3 < 768; i3++) {
            byte[] bArr4 = this.f762P;
            byte b14 = this.f766s;
            int i4 = i3 & 255;
            byte b15 = bArr4[i4];
            byte b16 = bArr4[(b14 + b15 + this.f763T[i3 & 31]) & 255];
            this.f766s = b16;
            bArr4[i4] = bArr4[b16 & UByte.MAX_VALUE];
            bArr4[b16 & UByte.MAX_VALUE] = b15;
        }
        byte[] bArr5 = new byte[20];
        for (int i5 = 0; i5 < 20; i5++) {
            byte[] bArr6 = this.f762P;
            int i6 = i5 & 255;
            byte b17 = bArr6[(this.f766s + bArr6[i6]) & 255];
            this.f766s = b17;
            bArr5[i5] = bArr6[(bArr6[bArr6[b17 & UByte.MAX_VALUE] & UByte.MAX_VALUE] + 1) & 255];
            byte b18 = bArr6[i6];
            bArr6[i6] = bArr6[b17 & UByte.MAX_VALUE];
            bArr6[b17 & UByte.MAX_VALUE] = b18;
        }
        System.arraycopy(bArr5, 0, bArr, i, 20);
        reset();
        return 20;
    }

    @Override // org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return "VMPC-MAC";
    }

    @Override // org.bouncycastle.crypto.Mac
    public int getMacSize() {
        return 20;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("VMPC-MAC Init parameters must include an IV");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        KeyParameter keyParameter = (KeyParameter) parametersWithIV.getParameters();
        if (!(parametersWithIV.getParameters() instanceof KeyParameter)) {
            throw new IllegalArgumentException("VMPC-MAC Init parameters must include a key");
        }
        byte[] iv = parametersWithIV.getIV();
        this.workingIV = iv;
        if (iv == null || iv.length < 1 || iv.length > 768) {
            throw new IllegalArgumentException("VMPC-MAC requires 1 to 768 bytes of IV");
        }
        this.workingKey = keyParameter.getKey();
        reset();
    }

    @Override // org.bouncycastle.crypto.Mac
    public void reset() {
        initKey(this.workingKey, this.workingIV);
        this.f765n = (byte) 0;
        this.f770x4 = (byte) 0;
        this.f769x3 = (byte) 0;
        this.f768x2 = (byte) 0;
        this.f767x1 = (byte) 0;
        this.f764g = (byte) 0;
        this.f763T = new byte[32];
        for (int i = 0; i < 32; i++) {
            this.f763T[i] = 0;
        }
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte b) throws IllegalStateException {
        byte[] bArr = this.f762P;
        byte b2 = this.f766s;
        byte b3 = this.f765n;
        byte b4 = bArr[(b2 + bArr[b3 & UByte.MAX_VALUE]) & 255];
        this.f766s = b4;
        byte b5 = this.f770x4;
        byte b6 = this.f769x3;
        byte b7 = bArr[(b5 + b6) & 255];
        this.f770x4 = b7;
        byte b8 = this.f768x2;
        byte b9 = bArr[(b6 + b8) & 255];
        this.f769x3 = b9;
        byte b10 = this.f767x1;
        byte b11 = bArr[(b8 + b10) & 255];
        this.f768x2 = b11;
        byte b12 = bArr[(b10 + b4 + ((byte) (b ^ bArr[(bArr[bArr[b4 & UByte.MAX_VALUE] & UByte.MAX_VALUE] + 1) & 255]))) & 255];
        this.f767x1 = b12;
        byte[] bArr2 = this.f763T;
        byte b13 = this.f764g;
        bArr2[b13 & 31] = (byte) (b12 ^ bArr2[b13 & 31]);
        bArr2[(b13 + 1) & 31] = (byte) (b11 ^ bArr2[(b13 + 1) & 31]);
        bArr2[(b13 + 2) & 31] = (byte) (b9 ^ bArr2[(b13 + 2) & 31]);
        bArr2[(b13 + 3) & 31] = (byte) (b7 ^ bArr2[(b13 + 3) & 31]);
        this.f764g = (byte) ((b13 + 4) & 31);
        byte b14 = bArr[b3 & UByte.MAX_VALUE];
        bArr[b3 & UByte.MAX_VALUE] = bArr[b4 & UByte.MAX_VALUE];
        bArr[b4 & UByte.MAX_VALUE] = b14;
        this.f765n = (byte) ((b3 + 1) & 255);
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        for (int i3 = 0; i3 < i2; i3++) {
            update(bArr[i + i3]);
        }
    }
}