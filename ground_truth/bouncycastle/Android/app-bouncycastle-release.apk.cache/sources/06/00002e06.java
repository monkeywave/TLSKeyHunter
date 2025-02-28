package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.AEADBlockCipher;
import org.bouncycastle.crypto.params.AEADParameters;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsAEADCipherImpl */
/* loaded from: classes2.dex */
final class BcTlsAEADCipherImpl implements TlsAEADCipherImpl {
    private final AEADBlockCipher cipher;
    private final boolean isEncrypting;
    private KeyParameter key;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTlsAEADCipherImpl(AEADBlockCipher aEADBlockCipher, boolean z) {
        this.cipher = aEADBlockCipher;
        this.isEncrypting = z;
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public int doFinal(byte[] bArr, byte[] bArr2, int i, int i2, byte[] bArr3, int i3) throws IOException {
        if (!Arrays.isNullOrEmpty(bArr)) {
            this.cipher.processAADBytes(bArr, 0, bArr.length);
        }
        int processBytes = this.cipher.processBytes(bArr2, i, i2, bArr3, i3);
        try {
            return processBytes + this.cipher.doFinal(bArr3, i3 + processBytes);
        } catch (InvalidCipherTextException e) {
            throw new TlsFatalAlert((short) 20, (Throwable) e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public int getOutputSize(int i) {
        return this.cipher.getOutputSize(i);
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public void init(byte[] bArr, int i) {
        this.cipher.init(this.isEncrypting, new AEADParameters(this.key, i * 8, bArr, null));
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public void setKey(byte[] bArr, int i, int i2) {
        this.key = new KeyParameter(bArr, i, i2);
    }
}