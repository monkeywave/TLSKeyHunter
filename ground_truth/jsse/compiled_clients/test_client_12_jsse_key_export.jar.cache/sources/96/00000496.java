package org.bouncycastle.crypto.engines;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.OutputLengthException;
import org.bouncycastle.crypto.StreamCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/VMPCEngine.class */
public class VMPCEngine implements StreamCipher {

    /* renamed from: n */
    protected byte f386n = 0;

    /* renamed from: P */
    protected byte[] f387P = null;

    /* renamed from: s */
    protected byte f388s = 0;
    protected byte[] workingIV;
    protected byte[] workingKey;

    @Override // org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "VMPC";
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void init(boolean z, CipherParameters cipherParameters) {
        if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("VMPC init parameters must include an IV");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        if (!(parametersWithIV.getParameters() instanceof KeyParameter)) {
            throw new IllegalArgumentException("VMPC init parameters must include a key");
        }
        KeyParameter keyParameter = (KeyParameter) parametersWithIV.getParameters();
        this.workingIV = parametersWithIV.getIV();
        if (this.workingIV == null || this.workingIV.length < 1 || this.workingIV.length > 768) {
            throw new IllegalArgumentException("VMPC requires 1 to 768 bytes of IV");
        }
        this.workingKey = keyParameter.getKey();
        initKey(this.workingKey, this.workingIV);
    }

    protected void initKey(byte[] bArr, byte[] bArr2) {
        this.f388s = (byte) 0;
        this.f387P = new byte[256];
        for (int i = 0; i < 256; i++) {
            this.f387P[i] = (byte) i;
        }
        for (int i2 = 0; i2 < 768; i2++) {
            this.f388s = this.f387P[(this.f388s + this.f387P[i2 & GF2Field.MASK] + bArr[i2 % bArr.length]) & GF2Field.MASK];
            byte b = this.f387P[i2 & GF2Field.MASK];
            this.f387P[i2 & GF2Field.MASK] = this.f387P[this.f388s & 255];
            this.f387P[this.f388s & 255] = b;
        }
        for (int i3 = 0; i3 < 768; i3++) {
            this.f388s = this.f387P[(this.f388s + this.f387P[i3 & GF2Field.MASK] + bArr2[i3 % bArr2.length]) & GF2Field.MASK];
            byte b2 = this.f387P[i3 & GF2Field.MASK];
            this.f387P[i3 & GF2Field.MASK] = this.f387P[this.f388s & 255];
            this.f387P[this.f388s & 255] = b2;
        }
        this.f386n = (byte) 0;
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
            this.f388s = this.f387P[(this.f388s + this.f387P[this.f386n & 255]) & GF2Field.MASK];
            byte b = this.f387P[(this.f387P[this.f387P[this.f388s & 255] & 255] + 1) & GF2Field.MASK];
            byte b2 = this.f387P[this.f386n & 255];
            this.f387P[this.f386n & 255] = this.f387P[this.f388s & 255];
            this.f387P[this.f388s & 255] = b2;
            this.f386n = (byte) ((this.f386n + 1) & GF2Field.MASK);
            bArr2[i4 + i3] = (byte) (bArr[i4 + i] ^ b);
        }
        return i2;
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public void reset() {
        initKey(this.workingKey, this.workingIV);
    }

    @Override // org.bouncycastle.crypto.StreamCipher
    public byte returnByte(byte b) {
        this.f388s = this.f387P[(this.f388s + this.f387P[this.f386n & 255]) & GF2Field.MASK];
        byte b2 = this.f387P[(this.f387P[this.f387P[this.f388s & 255] & 255] + 1) & GF2Field.MASK];
        byte b3 = this.f387P[this.f386n & 255];
        this.f387P[this.f386n & 255] = this.f387P[this.f388s & 255];
        this.f387P[this.f388s & 255] = b3;
        this.f386n = (byte) ((this.f386n + 1) & GF2Field.MASK);
        return (byte) (b ^ b2);
    }
}