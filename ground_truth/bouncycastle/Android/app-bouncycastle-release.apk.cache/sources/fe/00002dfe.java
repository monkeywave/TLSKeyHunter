package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import org.bouncycastle.asn1.cmc.BodyPartID;
import org.bouncycastle.crypto.engines.ChaCha7539Engine;
import org.bouncycastle.crypto.macs.Poly1305;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcChaCha20Poly1305 */
/* loaded from: classes2.dex */
public class BcChaCha20Poly1305 implements TlsAEADCipherImpl {
    private static final byte[] ZEROES = new byte[15];
    protected final boolean isEncrypting;
    protected final ChaCha7539Engine cipher = new ChaCha7539Engine();
    protected final Poly1305 mac = new Poly1305();

    public BcChaCha20Poly1305(boolean z) {
        this.isEncrypting = z;
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public int doFinal(byte[] bArr, byte[] bArr2, int i, int i2, byte[] bArr3, int i3) throws IOException {
        int i4;
        if (Arrays.isNullOrEmpty(bArr)) {
            i4 = 0;
        } else {
            int length = bArr.length;
            updateMAC(bArr, 0, bArr.length);
            i4 = length;
        }
        if (this.isEncrypting) {
            if (i2 == this.cipher.processBytes(bArr2, i, i2, bArr3, i3)) {
                updateMAC(bArr3, i3, i2);
                byte[] bArr4 = new byte[16];
                Pack.longToLittleEndian(i4 & BodyPartID.bodyIdMax, bArr4, 0);
                Pack.longToLittleEndian(i2 & BodyPartID.bodyIdMax, bArr4, 8);
                this.mac.update(bArr4, 0, 16);
                this.mac.doFinal(bArr3, i3 + i2);
                return i2 + 16;
            }
            throw new IllegalStateException();
        }
        int i5 = i2 - 16;
        updateMAC(bArr2, i, i5);
        byte[] bArr5 = new byte[16];
        Pack.longToLittleEndian(i4 & BodyPartID.bodyIdMax, bArr5, 0);
        Pack.longToLittleEndian(i5 & BodyPartID.bodyIdMax, bArr5, 8);
        this.mac.update(bArr5, 0, 16);
        this.mac.doFinal(bArr5, 0);
        if (TlsUtils.constantTimeAreEqual(16, bArr5, 0, bArr2, i + i5)) {
            if (i5 == this.cipher.processBytes(bArr2, i, i5, bArr3, i3)) {
                return i5;
            }
            throw new IllegalStateException();
        }
        throw new TlsFatalAlert((short) 20);
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public int getOutputSize(int i) {
        return this.isEncrypting ? i + 16 : i - 16;
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public void init(byte[] bArr, int i) throws IOException {
        if (bArr == null || bArr.length != 12 || i != 16) {
            throw new TlsFatalAlert((short) 80);
        }
        this.cipher.init(this.isEncrypting, new ParametersWithIV(null, bArr));
        initMAC();
    }

    protected void initMAC() {
        byte[] bArr = new byte[64];
        this.cipher.processBytes(bArr, 0, 64, bArr, 0);
        this.mac.init(new KeyParameter(bArr, 0, 32));
        Arrays.fill(bArr, (byte) 0);
    }

    @Override // org.bouncycastle.tls.crypto.impl.TlsAEADCipherImpl
    public void setKey(byte[] bArr, int i, int i2) throws IOException {
        this.cipher.init(this.isEncrypting, new ParametersWithIV(new KeyParameter(bArr, i, i2), ZEROES, 0, 12));
    }

    protected void updateMAC(byte[] bArr, int i, int i2) {
        this.mac.update(bArr, i, i2);
        int i3 = i2 % 16;
        if (i3 != 0) {
            this.mac.update(ZEROES, 0, 16 - i3);
        }
    }
}