package org.bouncycastle.tls.crypto.impl.jcajce;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.jcajce.util.JcaJceHelper;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class JceChaCha20Poly1305 implements TlsAEADCipherImpl {
    private static final byte[] ZEROES = new byte[15];
    protected final Cipher cipher;
    protected SecretKey cipherKey;
    protected final int cipherMode;
    protected final JcaTlsCrypto crypto;
    protected final Mac mac;

    public JceChaCha20Poly1305(JcaTlsCrypto jcaTlsCrypto, JcaJceHelper jcaJceHelper, boolean z) throws GeneralSecurityException {
        this.crypto = jcaTlsCrypto;
        this.cipher = jcaJceHelper.createCipher("ChaCha7539");
        this.mac = jcaJceHelper.createMac("Poly1305");
        this.cipherMode = z ? 1 : 2;
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public int doFinal(byte[] bArr, byte[] bArr2, int i, int i2, byte[] bArr3, int i3) throws IOException {
        int i4;
        int i5;
        try {
            if (this.cipherMode == 1) {
                byte[] bArr4 = new byte[i2 + 64];
                System.arraycopy(bArr2, i, bArr4, 64, i2);
                runCipher(bArr4);
                System.arraycopy(bArr4, 64, bArr3, i3, i2);
                initMAC(bArr4);
                if (Arrays.isNullOrEmpty(bArr)) {
                    i5 = 0;
                } else {
                    i5 = bArr.length;
                    updateMAC(bArr, 0, bArr.length);
                }
                updateMAC(bArr4, 64, i2);
                byte[] bArr5 = new byte[16];
                Pack.longToLittleEndian(i5 & BodyPartID.bodyIdMax, bArr5, 0);
                Pack.longToLittleEndian(i2 & BodyPartID.bodyIdMax, bArr5, 8);
                this.mac.update(bArr5, 0, 16);
                this.mac.doFinal(bArr3, i3 + i2);
                return i2 + 16;
            }
            int i6 = i2 - 16;
            byte[] bArr6 = new byte[i2 + 48];
            System.arraycopy(bArr2, i, bArr6, 64, i6);
            runCipher(bArr6);
            initMAC(bArr6);
            if (Arrays.isNullOrEmpty(bArr)) {
                i4 = 0;
            } else {
                i4 = bArr.length;
                updateMAC(bArr, 0, bArr.length);
            }
            updateMAC(bArr2, i, i6);
            byte[] bArr7 = new byte[16];
            Pack.longToLittleEndian(i4 & BodyPartID.bodyIdMax, bArr7, 0);
            Pack.longToLittleEndian(BodyPartID.bodyIdMax & i6, bArr7, 8);
            this.mac.update(bArr7, 0, 16);
            this.mac.doFinal(bArr7, 0);
            if (TlsUtils.constantTimeAreEqual(16, bArr7, 0, bArr2, i + i6)) {
                System.arraycopy(bArr6, 64, bArr3, i3, i6);
                return i6;
            }
            throw new TlsFatalAlert((short) 20);
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public int getOutputSize(int i) {
        return this.cipherMode == 1 ? i + 16 : i - 16;
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public void init(byte[] bArr, int i) throws IOException {
        if (bArr == null || bArr.length != 12 || i != 16) {
            throw new TlsFatalAlert((short) 80);
        }
        try {
            this.cipher.init(this.cipherMode, this.cipherKey, new IvParameterSpec(bArr), this.crypto.getSecureRandom());
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    protected void initMAC(byte[] bArr) throws InvalidKeyException {
        this.mac.init(new SecretKeySpec(bArr, 0, 32, "Poly1305"));
        for (int i = 0; i < 64; i++) {
            bArr[i] = 0;
        }
    }

    protected void runCipher(byte[] bArr) throws GeneralSecurityException {
        if (bArr.length != this.cipher.doFinal(bArr, 0, bArr.length, bArr, 0)) {
            throw new IllegalStateException();
        }
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public void setKey(byte[] bArr, int i, int i2) throws IOException {
        this.cipherKey = new SecretKeySpec(bArr, i, i2, "ChaCha7539");
    }

    protected void updateMAC(byte[] bArr, int i, int i2) {
        this.mac.update(bArr, i, i2);
        int i3 = i2 % 16;
        if (i3 != 0) {
            this.mac.update(ZEROES, 0, 16 - i3);
        }
    }
}