package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.GeneralSecurityException;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;

/* loaded from: classes2.dex */
public class JceBlockCipherWithCBCImplicitIVImpl implements TlsBlockCipherImpl {
    private static final int BUF_SIZE = 32768;
    private final String algorithm;
    private final Cipher cipher;
    private final int cipherMode;
    private final JcaTlsCrypto crypto;
    private SecretKey key;
    private byte[] nextIV;

    public JceBlockCipherWithCBCImplicitIVImpl(JcaTlsCrypto jcaTlsCrypto, Cipher cipher, String str, boolean z) throws GeneralSecurityException {
        this.crypto = jcaTlsCrypto;
        this.cipher = cipher;
        this.algorithm = str;
        this.cipherMode = z ? 1 : 2;
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl
    public int doFinal(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        try {
            this.cipher.init(this.cipherMode, this.key, new IvParameterSpec(this.nextIV), this.crypto.getSecureRandom());
            this.nextIV = null;
            if (1 != this.cipherMode) {
                int i4 = i + i2;
                this.nextIV = TlsUtils.copyOfRangeExact(bArr, i4 - this.cipher.getBlockSize(), i4);
            }
            int i5 = 0;
            while (i2 > 32768) {
                i5 += this.cipher.update(bArr, i, 32768, bArr2, i3 + i5);
                i += 32768;
                i2 -= 32768;
            }
            int update = i5 + this.cipher.update(bArr, i, i2, bArr2, i3 + i5);
            int doFinal = update + this.cipher.doFinal(bArr2, i3 + update);
            if (1 == this.cipherMode) {
                int i6 = i3 + doFinal;
                this.nextIV = TlsUtils.copyOfRangeExact(bArr2, i6 - this.cipher.getBlockSize(), i6);
            }
            return doFinal;
        } catch (GeneralSecurityException e) {
            throw Exceptions.illegalStateException(e.getMessage(), e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl
    public void init(byte[] bArr, int i, int i2) {
        if (this.nextIV != null) {
            throw new IllegalStateException("unexpected reinitialization of an implicit-IV cipher");
        }
        this.nextIV = TlsUtils.copyOfRangeExact(bArr, i, i2 + i);
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl
    public void setKey(byte[] bArr, int i, int i2) {
        this.key = new SecretKeySpec(bArr, i, i2, this.algorithm);
    }
}