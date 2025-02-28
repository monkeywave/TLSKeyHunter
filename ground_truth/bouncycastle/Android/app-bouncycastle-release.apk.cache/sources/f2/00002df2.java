package org.bouncycastle.tls.crypto.impl;

import java.io.IOException;
import org.bouncycastle.tls.crypto.TlsEncryptor;
import org.bouncycastle.tls.crypto.TlsHMAC;
import org.bouncycastle.tls.crypto.TlsSecret;
import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public abstract class AbstractTlsSecret implements TlsSecret {
    protected byte[] data;

    /* JADX INFO: Access modifiers changed from: protected */
    public AbstractTlsSecret(byte[] bArr) {
        this.data = bArr;
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public static byte[] copyData(AbstractTlsSecret abstractTlsSecret) {
        return abstractTlsSecret.copyData();
    }

    @Override // org.bouncycastle.tls.crypto.TlsSecret
    public synchronized byte[] calculateHMAC(int i, byte[] bArr, int i2, int i3) {
        TlsHMAC createHMACForHash;
        checkAlive();
        createHMACForHash = getCrypto().createHMACForHash(i);
        byte[] bArr2 = this.data;
        createHMACForHash.setKey(bArr2, 0, bArr2.length);
        createHMACForHash.update(bArr, i2, i3);
        return createHMACForHash.calculateMAC();
    }

    /* JADX INFO: Access modifiers changed from: protected */
    public void checkAlive() {
        if (this.data == null) {
            throw new IllegalStateException("Secret has already been extracted or destroyed");
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public synchronized byte[] copyData() {
        return Arrays.clone(this.data);
    }

    @Override // org.bouncycastle.tls.crypto.TlsSecret
    public synchronized void destroy() {
        byte[] bArr = this.data;
        if (bArr != null) {
            Arrays.fill(bArr, (byte) 0);
            this.data = null;
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsSecret
    public synchronized byte[] encrypt(TlsEncryptor tlsEncryptor) throws IOException {
        byte[] bArr;
        checkAlive();
        bArr = this.data;
        return tlsEncryptor.encrypt(bArr, 0, bArr.length);
    }

    @Override // org.bouncycastle.tls.crypto.TlsSecret
    public synchronized byte[] extract() {
        byte[] bArr;
        checkAlive();
        bArr = this.data;
        this.data = null;
        return bArr;
    }

    protected abstract AbstractTlsCrypto getCrypto();

    @Override // org.bouncycastle.tls.crypto.TlsSecret
    public synchronized boolean isAlive() {
        return this.data != null;
    }
}