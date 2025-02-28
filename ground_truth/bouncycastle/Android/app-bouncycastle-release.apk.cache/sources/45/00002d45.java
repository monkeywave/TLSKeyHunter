package org.bouncycastle.tls;

import java.io.IOException;
import java.io.OutputStream;
import java.util.Enumeration;
import java.util.Hashtable;
import org.bouncycastle.tls.crypto.TlsHash;
import org.bouncycastle.util.Integers;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class DeferredHash implements TlsHandshakeHash {
    protected static final int BUFFERING_HASH_LIMIT = 4;
    protected TlsContext context;
    private DigestInputBuffer buf = new DigestInputBuffer();
    private Hashtable hashes = new Hashtable();
    private boolean forceBuffering = false;
    private boolean sealed = false;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DeferredHash(TlsContext tlsContext) {
        this.context = tlsContext;
    }

    protected Integer box(int i) {
        return Integers.valueOf(i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public byte[] calculateHash() {
        throw new IllegalStateException("Use 'forkPRFHash' to get a definite hash");
    }

    protected void checkStopBuffering() {
        if (this.forceBuffering || !this.sealed || this.buf == null || this.hashes.size() > 4) {
            return;
        }
        Enumeration elements = this.hashes.elements();
        while (elements.hasMoreElements()) {
            this.buf.updateDigest((TlsHash) elements.nextElement());
        }
        this.buf = null;
    }

    protected void checkTrackingHash(int i) {
        checkTrackingHash(box(i));
    }

    protected void checkTrackingHash(Integer num) {
        if (this.hashes.containsKey(num)) {
            return;
        }
        this.hashes.put(num, this.context.getCrypto().createHash(num.intValue()));
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public TlsHash cloneHash() {
        throw new IllegalStateException("attempt to clone a DeferredHash");
    }

    protected TlsHash cloneHash(int i) {
        return cloneHash(box(i));
    }

    protected TlsHash cloneHash(Integer num) {
        return ((TlsHash) this.hashes.get(num)).cloneHash();
    }

    protected void cloneHash(Hashtable hashtable, int i) {
        cloneHash(hashtable, box(i));
    }

    protected void cloneHash(Hashtable hashtable, Integer num) {
        TlsHash cloneHash = cloneHash(num);
        DigestInputBuffer digestInputBuffer = this.buf;
        if (digestInputBuffer != null) {
            digestInputBuffer.updateDigest(cloneHash);
        }
        hashtable.put(num, cloneHash);
    }

    @Override // org.bouncycastle.tls.TlsHandshakeHash
    public void copyBufferTo(OutputStream outputStream) throws IOException {
        DigestInputBuffer digestInputBuffer = this.buf;
        if (digestInputBuffer == null) {
            throw new IllegalStateException("Not buffering");
        }
        digestInputBuffer.copyInputTo(outputStream);
    }

    @Override // org.bouncycastle.tls.TlsHandshakeHash
    public void forceBuffering() {
        if (this.sealed) {
            throw new IllegalStateException("Too late to force buffering");
        }
        this.forceBuffering = true;
    }

    @Override // org.bouncycastle.tls.TlsHandshakeHash
    public TlsHash forkPRFHash() {
        TlsHash combinedHash;
        checkStopBuffering();
        SecurityParameters securityParametersHandshake = this.context.getSecurityParametersHandshake();
        int pRFAlgorithm = securityParametersHandshake.getPRFAlgorithm();
        if (pRFAlgorithm == 0 || pRFAlgorithm == 1) {
            combinedHash = new CombinedHash(this.context, cloneHash(1), cloneHash(2));
        } else {
            combinedHash = cloneHash(securityParametersHandshake.getPRFCryptoHashAlgorithm());
        }
        DigestInputBuffer digestInputBuffer = this.buf;
        if (digestInputBuffer != null) {
            digestInputBuffer.updateDigest(combinedHash);
        }
        return combinedHash;
    }

    @Override // org.bouncycastle.tls.TlsHandshakeHash
    public byte[] getFinalHash(int i) {
        TlsHash tlsHash = (TlsHash) this.hashes.get(box(i));
        if (tlsHash != null) {
            checkStopBuffering();
            TlsHash cloneHash = tlsHash.cloneHash();
            DigestInputBuffer digestInputBuffer = this.buf;
            if (digestInputBuffer != null) {
                digestInputBuffer.updateDigest(cloneHash);
            }
            return cloneHash.calculateHash();
        }
        throw new IllegalStateException("CryptoHashAlgorithm." + i + " is not being tracked");
    }

    @Override // org.bouncycastle.tls.TlsHandshakeHash
    public void notifyPRFDetermined() {
        int i;
        SecurityParameters securityParametersHandshake = this.context.getSecurityParametersHandshake();
        int pRFAlgorithm = securityParametersHandshake.getPRFAlgorithm();
        if (pRFAlgorithm == 0 || pRFAlgorithm == 1) {
            checkTrackingHash(1);
            i = 2;
        } else {
            i = securityParametersHandshake.getPRFCryptoHashAlgorithm();
        }
        checkTrackingHash(i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public void reset() {
        DigestInputBuffer digestInputBuffer = this.buf;
        if (digestInputBuffer != null) {
            digestInputBuffer.reset();
            return;
        }
        Enumeration elements = this.hashes.elements();
        while (elements.hasMoreElements()) {
            ((TlsHash) elements.nextElement()).reset();
        }
    }

    @Override // org.bouncycastle.tls.TlsHandshakeHash
    public void sealHashAlgorithms() {
        if (this.sealed) {
            throw new IllegalStateException("Already sealed");
        }
        this.sealed = true;
        checkStopBuffering();
    }

    @Override // org.bouncycastle.tls.TlsHandshakeHash
    public void stopTracking() {
        int i;
        SecurityParameters securityParametersHandshake = this.context.getSecurityParametersHandshake();
        Hashtable hashtable = new Hashtable();
        int pRFAlgorithm = securityParametersHandshake.getPRFAlgorithm();
        if (pRFAlgorithm == 0 || pRFAlgorithm == 1) {
            cloneHash(hashtable, 1);
            i = 2;
        } else {
            i = securityParametersHandshake.getPRFCryptoHashAlgorithm();
        }
        cloneHash(hashtable, i);
        this.buf = null;
        this.hashes = hashtable;
        this.forceBuffering = false;
        this.sealed = true;
    }

    @Override // org.bouncycastle.tls.TlsHandshakeHash
    public void trackHashAlgorithm(int i) {
        if (this.sealed) {
            throw new IllegalStateException("Too late to track more hash algorithms");
        }
        checkTrackingHash(i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsHash
    public void update(byte[] bArr, int i, int i2) {
        DigestInputBuffer digestInputBuffer = this.buf;
        if (digestInputBuffer != null) {
            digestInputBuffer.write(bArr, i, i2);
            return;
        }
        Enumeration elements = this.hashes.elements();
        while (elements.hasMoreElements()) {
            ((TlsHash) elements.nextElement()).update(bArr, i, i2);
        }
    }
}