package org.bouncycastle.crypto.macs;

import javassist.bytecode.Opcode;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.crypto.params.ParametersWithSBox;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/macs/GOST28147Mac.class */
public class GOST28147Mac implements Mac {
    private int blockSize = 8;
    private int macSize = 4;
    private boolean firstStep = true;
    private int[] workingKey = null;
    private byte[] macIV = null;

    /* renamed from: S */
    private byte[] f415S = {9, 6, 3, 2, 8, 11, 1, 7, 10, 4, 14, 15, 12, 0, 13, 5, 3, 7, 14, 9, 8, 10, 15, 0, 5, 2, 6, 12, 11, 4, 13, 1, 14, 4, 6, 2, 11, 3, 13, 8, 12, 15, 5, 10, 0, 7, 1, 9, 14, 7, 10, 12, 13, 1, 3, 9, 0, 2, 11, 4, 15, 8, 5, 6, 11, 5, 1, 9, 8, 13, 15, 0, 14, 4, 2, 3, 12, 7, 10, 6, 3, 10, 13, 12, 1, 2, 0, 11, 7, 5, 9, 4, 8, 15, 14, 6, 1, 13, 2, 9, 7, 10, 6, 0, 8, 12, 4, 5, 15, 3, 11, 14, 11, 10, 15, 5, 0, 12, 14, 8, 6, 2, 3, 9, 1, 7, 13, 4};
    private byte[] mac = new byte[this.blockSize];
    private byte[] buf = new byte[this.blockSize];
    private int bufOff = 0;

    private int[] generateWorkingKey(byte[] bArr) {
        if (bArr.length != 32) {
            throw new IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!");
        }
        int[] iArr = new int[8];
        for (int i = 0; i != 8; i++) {
            iArr[i] = bytesToint(bArr, i * 4);
        }
        return iArr;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        reset();
        this.buf = new byte[this.blockSize];
        this.macIV = null;
        recursiveInit(cipherParameters);
    }

    private void recursiveInit(CipherParameters cipherParameters) throws IllegalArgumentException {
        if (cipherParameters == null) {
            return;
        }
        CipherParameters cipherParameters2 = null;
        if (cipherParameters instanceof ParametersWithSBox) {
            ParametersWithSBox parametersWithSBox = (ParametersWithSBox) cipherParameters;
            System.arraycopy(parametersWithSBox.getSBox(), 0, this.f415S, 0, parametersWithSBox.getSBox().length);
            cipherParameters2 = parametersWithSBox.getParameters();
        } else if (cipherParameters instanceof KeyParameter) {
            this.workingKey = generateWorkingKey(((KeyParameter) cipherParameters).getKey());
        } else if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("invalid parameter passed to GOST28147 init - " + cipherParameters.getClass().getName());
        } else {
            ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
            System.arraycopy(parametersWithIV.getIV(), 0, this.mac, 0, this.mac.length);
            this.macIV = parametersWithIV.getIV();
            cipherParameters2 = parametersWithIV.getParameters();
        }
        recursiveInit(cipherParameters2);
    }

    @Override // org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return "GOST28147Mac";
    }

    @Override // org.bouncycastle.crypto.Mac
    public int getMacSize() {
        return this.macSize;
    }

    private int gost28147_mainStep(int i, int i2) {
        int i3 = i2 + i;
        int i4 = (this.f415S[0 + ((i3 >> 0) & 15)] << 0) + (this.f415S[16 + ((i3 >> 4) & 15)] << 4) + (this.f415S[32 + ((i3 >> 8) & 15)] << 8) + (this.f415S[48 + ((i3 >> 12) & 15)] << 12) + (this.f415S[64 + ((i3 >> 16) & 15)] << 16) + (this.f415S[80 + ((i3 >> 20) & 15)] << 20) + (this.f415S[96 + ((i3 >> 24) & 15)] << 24) + (this.f415S[Opcode.IREM + ((i3 >> 28) & 15)] << 28);
        return (i4 << 11) | (i4 >>> 21);
    }

    private void gost28147MacFunc(int[] iArr, byte[] bArr, int i, byte[] bArr2, int i2) {
        int bytesToint = bytesToint(bArr, i);
        int bytesToint2 = bytesToint(bArr, i + 4);
        for (int i3 = 0; i3 < 2; i3++) {
            for (int i4 = 0; i4 < 8; i4++) {
                int i5 = bytesToint;
                bytesToint = bytesToint2 ^ gost28147_mainStep(bytesToint, iArr[i4]);
                bytesToint2 = i5;
            }
        }
        intTobytes(bytesToint, bArr2, i2);
        intTobytes(bytesToint2, bArr2, i2 + 4);
    }

    private int bytesToint(byte[] bArr, int i) {
        return ((bArr[i + 3] << 24) & (-16777216)) + ((bArr[i + 2] << 16) & 16711680) + ((bArr[i + 1] << 8) & 65280) + (bArr[i] & 255);
    }

    private void intTobytes(int i, byte[] bArr, int i2) {
        bArr[i2 + 3] = (byte) (i >>> 24);
        bArr[i2 + 2] = (byte) (i >>> 16);
        bArr[i2 + 1] = (byte) (i >>> 8);
        bArr[i2] = (byte) i;
    }

    private byte[] CM5func(byte[] bArr, int i, byte[] bArr2) {
        byte[] bArr3 = new byte[bArr.length - i];
        System.arraycopy(bArr, i, bArr3, 0, bArr2.length);
        for (int i2 = 0; i2 != bArr2.length; i2++) {
            bArr3[i2] = (byte) (bArr3[i2] ^ bArr2[i2]);
        }
        return bArr3;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte b) throws IllegalStateException {
        if (this.bufOff == this.buf.length) {
            byte[] bArr = new byte[this.buf.length];
            System.arraycopy(this.buf, 0, bArr, 0, this.mac.length);
            if (this.firstStep) {
                this.firstStep = false;
                if (this.macIV != null) {
                    bArr = CM5func(this.buf, 0, this.macIV);
                }
            } else {
                bArr = CM5func(this.buf, 0, this.mac);
            }
            gost28147MacFunc(this.workingKey, bArr, 0, this.mac, 0);
            this.bufOff = 0;
        }
        byte[] bArr2 = this.buf;
        int i = this.bufOff;
        this.bufOff = i + 1;
        bArr2[i] = b;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        if (i2 < 0) {
            throw new IllegalArgumentException("Can't have a negative input length!");
        }
        int i3 = this.blockSize - this.bufOff;
        if (i2 > i3) {
            System.arraycopy(bArr, i, this.buf, this.bufOff, i3);
            byte[] bArr2 = new byte[this.buf.length];
            System.arraycopy(this.buf, 0, bArr2, 0, this.mac.length);
            if (this.firstStep) {
                this.firstStep = false;
                if (this.macIV != null) {
                    bArr2 = CM5func(this.buf, 0, this.macIV);
                }
            } else {
                bArr2 = CM5func(this.buf, 0, this.mac);
            }
            gost28147MacFunc(this.workingKey, bArr2, 0, this.mac, 0);
            this.bufOff = 0;
            i2 -= i3;
            int i4 = i;
            int i5 = i3;
            while (true) {
                i = i4 + i5;
                if (i2 <= this.blockSize) {
                    break;
                }
                gost28147MacFunc(this.workingKey, CM5func(bArr, i, this.mac), 0, this.mac, 0);
                i2 -= this.blockSize;
                i4 = i;
                i5 = this.blockSize;
            }
        }
        System.arraycopy(bArr, i, this.buf, this.bufOff, i2);
        this.bufOff += i2;
    }

    @Override // org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        while (this.bufOff < this.blockSize) {
            this.buf[this.bufOff] = 0;
            this.bufOff++;
        }
        byte[] bArr2 = new byte[this.buf.length];
        System.arraycopy(this.buf, 0, bArr2, 0, this.mac.length);
        if (this.firstStep) {
            this.firstStep = false;
        } else {
            bArr2 = CM5func(this.buf, 0, this.mac);
        }
        gost28147MacFunc(this.workingKey, bArr2, 0, this.mac, 0);
        System.arraycopy(this.mac, (this.mac.length / 2) - this.macSize, bArr, i, this.macSize);
        reset();
        return this.macSize;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void reset() {
        for (int i = 0; i < this.buf.length; i++) {
            this.buf[i] = 0;
        }
        this.bufOff = 0;
        this.firstStep = true;
    }
}