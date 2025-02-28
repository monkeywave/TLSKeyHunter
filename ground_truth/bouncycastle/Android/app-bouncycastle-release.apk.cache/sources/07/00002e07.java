package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsBlockCipherImpl */
/* loaded from: classes2.dex */
final class BcTlsBlockCipherImpl implements TlsBlockCipherImpl {
    private final BlockCipher cipher;
    private final boolean isEncrypting;
    private KeyParameter key;

    /* JADX INFO: Access modifiers changed from: package-private */
    public BcTlsBlockCipherImpl(BlockCipher blockCipher, boolean z) {
        this.cipher = blockCipher;
        this.isEncrypting = z;
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl
    public int doFinal(byte[] bArr, int i, int i2, byte[] bArr2, int i3) {
        int blockSize = this.cipher.getBlockSize();
        for (int i4 = 0; i4 < i2; i4 += blockSize) {
            this.cipher.processBlock(bArr, i + i4, bArr2, i3 + i4);
        }
        return i2;
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl
    public int getBlockSize() {
        return this.cipher.getBlockSize();
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl
    public void init(byte[] bArr, int i, int i2) {
        this.cipher.init(this.isEncrypting, new ParametersWithIV(this.key, bArr, i, i2));
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsBlockCipherImpl
    public void setKey(byte[] bArr, int i, int i2) {
        this.key = new KeyParameter(bArr, i, i2);
    }
}