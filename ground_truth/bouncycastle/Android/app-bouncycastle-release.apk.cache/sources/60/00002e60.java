package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.InvalidKeyException;
import javax.crypto.Mac;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.tls.crypto.TlsCryptoUtils;
import org.bouncycastle.tls.crypto.TlsHMAC;

/* loaded from: classes2.dex */
public class JceTlsHMAC implements TlsHMAC {
    private final String algorithm;
    private final Mac hmac;
    private final int internalBlockSize;

    public JceTlsHMAC(int i, Mac mac, String str) {
        this.hmac = mac;
        this.algorithm = str;
        this.internalBlockSize = TlsCryptoUtils.getHashInternalSize(i);
    }

    @Override // org.bouncycastle.tls.crypto.TlsMAC
    public void calculateMAC(byte[] bArr, int i) {
        try {
            this.hmac.doFinal(bArr, i);
        } catch (ShortBufferException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsMAC
    public byte[] calculateMAC() {
        return this.hmac.doFinal();
    }

    @Override // org.bouncycastle.tls.crypto.TlsHMAC
    public int getInternalBlockSize() {
        return this.internalBlockSize;
    }

    @Override // org.bouncycastle.tls.crypto.TlsMAC
    public int getMacLength() {
        return this.hmac.getMacLength();
    }

    @Override // org.bouncycastle.tls.crypto.TlsMAC
    public void reset() {
        this.hmac.reset();
    }

    @Override // org.bouncycastle.tls.crypto.TlsMAC
    public void setKey(byte[] bArr, int i, int i2) {
        try {
            this.hmac.init(new SecretKeySpec(bArr, i, i2, this.algorithm));
        } catch (InvalidKeyException e) {
            throw new IllegalArgumentException(e.getMessage());
        }
    }

    @Override // org.bouncycastle.tls.crypto.TlsMAC
    public void update(byte[] bArr, int i, int i2) {
        this.hmac.update(bArr, i, i2);
    }
}