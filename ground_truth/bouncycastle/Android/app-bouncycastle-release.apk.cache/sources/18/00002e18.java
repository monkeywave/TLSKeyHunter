package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.Digest;
import org.bouncycastle.tls.crypto.TlsHash;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsHash */
/* loaded from: classes2.dex */
final class BcTlsHash implements TlsHash {
    private final BcTlsCrypto crypto;
    private final int cryptoHashAlgorithm;
    private final Digest digest;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTlsHash(BcTlsCrypto bcTlsCrypto, int i) {
        this(bcTlsCrypto, i, bcTlsCrypto.createDigest(i));
    }

    private BcTlsHash(BcTlsCrypto bcTlsCrypto, int i, Digest digest) {
        this.crypto = bcTlsCrypto;
        this.cryptoHashAlgorithm = i;
        this.digest = digest;
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public byte[] calculateHash() {
        byte[] bArr = new byte[this.digest.getDigestSize()];
        this.digest.doFinal(bArr, 0);
        return bArr;
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public TlsHash cloneHash() {
        BcTlsCrypto bcTlsCrypto = this.crypto;
        int i = this.cryptoHashAlgorithm;
        return new BcTlsHash(bcTlsCrypto, i, bcTlsCrypto.cloneDigest(i, this.digest));
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public void reset() {
        this.digest.reset();
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public void update(byte[] bArr, int i, int i2) {
        this.digest.update(bArr, i, i2);
    }
}