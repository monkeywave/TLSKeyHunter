package org.bouncycastle.crypto.engines;

import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/VMPCKSA3Engine.class */
public class VMPCKSA3Engine extends VMPCEngine {
    @Override // org.bouncycastle.crypto.engines.VMPCEngine, org.bouncycastle.crypto.StreamCipher
    public String getAlgorithmName() {
        return "VMPC-KSA3";
    }

    @Override // org.bouncycastle.crypto.engines.VMPCEngine
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
        for (int i4 = 0; i4 < 768; i4++) {
            this.f388s = this.f387P[(this.f388s + this.f387P[i4 & GF2Field.MASK] + bArr[i4 % bArr.length]) & GF2Field.MASK];
            byte b3 = this.f387P[i4 & GF2Field.MASK];
            this.f387P[i4 & GF2Field.MASK] = this.f387P[this.f388s & 255];
            this.f387P[this.f388s & 255] = b3;
        }
        this.f386n = (byte) 0;
    }
}