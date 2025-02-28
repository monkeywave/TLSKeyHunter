package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsCrypto;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class CombinedHash implements TlsHash {
    protected TlsContext context;
    protected TlsCrypto crypto;
    protected TlsHash md5;
    protected TlsHash sha1;

    public CombinedHash(CombinedHash combinedHash) {
        this.context = combinedHash.context;
        this.crypto = combinedHash.crypto;
        this.md5 = combinedHash.md5.cloneHash();
        this.sha1 = combinedHash.sha1.cloneHash();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public CombinedHash(TlsContext tlsContext, TlsHash tlsHash, TlsHash tlsHash2) {
        this.context = tlsContext;
        this.crypto = tlsContext.getCrypto();
        this.md5 = tlsHash;
        this.sha1 = tlsHash2;
    }

    public CombinedHash(TlsCrypto tlsCrypto) {
        this.crypto = tlsCrypto;
        this.md5 = tlsCrypto.createHash(1);
        this.sha1 = tlsCrypto.createHash(2);
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public byte[] calculateHash() {
        TlsContext tlsContext = this.context;
        if (tlsContext != null && TlsUtils.isSSL(tlsContext)) {
            SSL3Utils.completeCombinedHash(this.context, this.md5, this.sha1);
        }
        return Arrays.concatenate(this.md5.calculateHash(), this.sha1.calculateHash());
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public TlsHash cloneHash() {
        return new CombinedHash(this);
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public void reset() {
        this.md5.reset();
        this.sha1.reset();
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public void update(byte[] bArr, int i, int i2) {
        this.md5.update(bArr, i, i2);
        this.sha1.update(bArr, i, i2);
    }
}