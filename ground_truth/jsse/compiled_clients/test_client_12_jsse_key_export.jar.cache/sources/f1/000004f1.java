package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.util.Pack;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/macs/SipHash128.class */
public class SipHash128 extends SipHash {
    public SipHash128() {
    }

    public SipHash128(int i, int i2) {
        super(i, i2);
    }

    @Override // org.bouncycastle.crypto.macs.SipHash, org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return "SipHash128-" + this.f435c + "-" + this.f436d;
    }

    @Override // org.bouncycastle.crypto.macs.SipHash, org.bouncycastle.crypto.Mac
    public int getMacSize() {
        return 16;
    }

    @Override // org.bouncycastle.crypto.macs.SipHash
    public long doFinal() throws DataLengthException, IllegalStateException {
        throw new UnsupportedOperationException("doFinal() is not supported");
    }

    @Override // org.bouncycastle.crypto.macs.SipHash, org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        this.f443m >>>= (7 - this.wordPos) << 3;
        this.f443m >>>= 8;
        this.f443m |= (((this.wordCount << 3) + this.wordPos) & 255) << 56;
        processMessageWord();
        this.f441v2 ^= 238;
        applySipRounds(this.f436d);
        long j = ((this.f439v0 ^ this.f440v1) ^ this.f441v2) ^ this.f442v3;
        this.f440v1 ^= 221;
        applySipRounds(this.f436d);
        reset();
        Pack.longToLittleEndian(j, bArr, i);
        Pack.longToLittleEndian(((this.f439v0 ^ this.f440v1) ^ this.f441v2) ^ this.f442v3, bArr, i + 8);
        return 16;
    }

    @Override // org.bouncycastle.crypto.macs.SipHash, org.bouncycastle.crypto.Mac
    public void reset() {
        super.reset();
        this.f440v1 ^= 238;
    }
}