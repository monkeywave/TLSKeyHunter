package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class SipHash128 extends SipHash {
    public SipHash128() {
    }

    public SipHash128(int i, int i2) {
        super(i, i2);
    }

    @Override // org.bouncycastle.crypto.macs.SipHash, org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        this.f757m >>>= (7 - this.wordPos) << 3;
        this.f757m >>>= 8;
        this.f757m |= (((this.wordCount << 3) + this.wordPos) & 255) << 56;
        processMessageWord();
        this.f760v2 ^= 238;
        applySipRounds(this.f754d);
        long j = ((this.f758v0 ^ this.f759v1) ^ this.f760v2) ^ this.f761v3;
        this.f759v1 ^= 221;
        applySipRounds(this.f754d);
        reset();
        Pack.longToLittleEndian(j, bArr, i);
        Pack.longToLittleEndian(((this.f758v0 ^ this.f759v1) ^ this.f760v2) ^ this.f761v3, bArr, i + 8);
        return 16;
    }

    @Override // org.bouncycastle.crypto.macs.SipHash
    public long doFinal() throws DataLengthException, IllegalStateException {
        throw new UnsupportedOperationException("doFinal() is not supported");
    }

    @Override // org.bouncycastle.crypto.macs.SipHash, org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return "SipHash128-" + this.f753c + "-" + this.f754d;
    }

    @Override // org.bouncycastle.crypto.macs.SipHash, org.bouncycastle.crypto.Mac
    public int getMacSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.macs.SipHash, org.bouncycastle.crypto.Mac
    public void reset() {
        super.reset();
        this.f759v1 ^= 238;
    }
}