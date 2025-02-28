package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/RC4Engine.class */
public class RC4Engine implements StreamCipher {
    private static final int STATE_LENGTH = 256;
    private byte[] engineState = null;

    /* renamed from: x */
    private int f353x = 0;

    /* renamed from: y */
    private int f354y = 0;
    private byte[] workingKey = null;

    @Override // org.bouncycastle.crypto.StreamCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof KeyParameter)) {
            throw new IllegalArgumentException("invalid parameter passed to RC4 init - " + cipherParameters.getClass().getName());
        }
        this.workingKey = ((KeyParameter) cipherParameters).getKey();
        setKey(this.workingKey);
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "RC4";
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public byte returnByte(byte b) {
        this.f353x = (this.f353x + 1) & GF2Field.MASK;
        this.f354y = (this.engineState[this.f353x] + this.f354y) & GF2Field.MASK;
        byte b2 = this.engineState[this.f353x];
        this.engineState[this.f353x] = this.engineState[this.f354y];
        this.engineState[this.f354y] = b2;
        return (byte) (b ^ this.engineState[(this.engineState[this.f353x] + this.engineState[this.f354y]) & GF2Field.MASK]);
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public int processBytes(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        if (i3 + i2 > bArr2.length) {
            throw new OutputLengthException("output buffer too short");
        }
        for (int i4 = 0; i4 < i2; i4++) {
            this.f353x = (this.f353x + 1) & GF2Field.MASK;
            this.f354y = (this.engineState[this.f353x] + this.f354y) & GF2Field.MASK;
            byte b = this.engineState[this.f353x];
            this.engineState[this.f353x] = this.engineState[this.f354y];
            this.engineState[this.f354y] = b;
            bArr2[i4 + i3] = (byte) (bArr[i4 + i] ^ this.engineState[(this.engineState[this.f353x] + this.engineState[this.f354y]) & GF2Field.MASK]);
        }
        return i2;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void reset() {
        setKey(this.workingKey);
    }

    private void setKey(byte[] bArr) {
        this.workingKey = bArr;
        this.f353x = 0;
        this.f354y = 0;
        if (this.engineState == null) {
            this.engineState = new byte[256];
        }
        for (int i = 0; i < 256; i++) {
            this.engineState[i] = (byte) i;
        }
        int i2 = 0;
        int i3 = 0;
        for (int i4 = 0; i4 < 256; i4++) {
            i3 = ((bArr[i2] & 255) + this.engineState[i4] + i3) & GF2Field.MASK;
            byte b = this.engineState[i4];
            this.engineState[i4] = this.engineState[i3];
            this.engineState[i3] = b;
            i2 = (i2 + 1) % bArr.length;
        }
    }
}