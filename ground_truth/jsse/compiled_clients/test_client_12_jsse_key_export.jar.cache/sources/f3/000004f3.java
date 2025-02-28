package org.bouncycastle.crypto.macs;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Mac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/macs/VMPCMac.class */
public class VMPCMac implements Mac {

    /* renamed from: g */
    private byte f444g;

    /* renamed from: n */
    private byte f445n = 0;

    /* renamed from: P */
    private byte[] f446P = null;

    /* renamed from: s */
    private byte f447s = 0;

    /* renamed from: T */
    private byte[] f448T;
    private byte[] workingIV;
    private byte[] workingKey;

    /* renamed from: x1 */
    private byte f449x1;

    /* renamed from: x2 */
    private byte f450x2;

    /* renamed from: x3 */
    private byte f451x3;

    /* renamed from: x4 */
    private byte f452x4;

    @Override // org.bouncycastle.crypto.Mac
    public int doFinal(byte[] bArr, int i) throws DataLengthException, IllegalStateException {
        for (int i2 = 1; i2 < 25; i2++) {
            this.f447s = this.f446P[(this.f447s + this.f446P[this.f445n & 255]) & GF2Field.MASK];
            this.f452x4 = this.f446P[(this.f452x4 + this.f451x3 + i2) & GF2Field.MASK];
            this.f451x3 = this.f446P[(this.f451x3 + this.f450x2 + i2) & GF2Field.MASK];
            this.f450x2 = this.f446P[(this.f450x2 + this.f449x1 + i2) & GF2Field.MASK];
            this.f449x1 = this.f446P[(this.f449x1 + this.f447s + i2) & GF2Field.MASK];
            this.f448T[this.f444g & 31] = (byte) (this.f448T[this.f444g & 31] ^ this.f449x1);
            this.f448T[(this.f444g + 1) & 31] = (byte) (this.f448T[(this.f444g + 1) & 31] ^ this.f450x2);
            this.f448T[(this.f444g + 2) & 31] = (byte) (this.f448T[(this.f444g + 2) & 31] ^ this.f451x3);
            this.f448T[(this.f444g + 3) & 31] = (byte) (this.f448T[(this.f444g + 3) & 31] ^ this.f452x4);
            this.f444g = (byte) ((this.f444g + 4) & 31);
            byte b = this.f446P[this.f445n & 255];
            this.f446P[this.f445n & 255] = this.f446P[this.f447s & 255];
            this.f446P[this.f447s & 255] = b;
            this.f445n = (byte) ((this.f445n + 1) & GF2Field.MASK);
        }
        for (int i3 = 0; i3 < 768; i3++) {
            this.f447s = this.f446P[(this.f447s + this.f446P[i3 & GF2Field.MASK] + this.f448T[i3 & 31]) & GF2Field.MASK];
            byte b2 = this.f446P[i3 & GF2Field.MASK];
            this.f446P[i3 & GF2Field.MASK] = this.f446P[this.f447s & 255];
            this.f446P[this.f447s & 255] = b2;
        }
        byte[] bArr2 = new byte[20];
        for (int i4 = 0; i4 < 20; i4++) {
            this.f447s = this.f446P[(this.f447s + this.f446P[i4 & GF2Field.MASK]) & GF2Field.MASK];
            bArr2[i4] = this.f446P[(this.f446P[this.f446P[this.f447s & 255] & 255] + 1) & GF2Field.MASK];
            byte b3 = this.f446P[i4 & GF2Field.MASK];
            this.f446P[i4 & GF2Field.MASK] = this.f446P[this.f447s & 255];
            this.f446P[this.f447s & 255] = b3;
        }
        System.arraycopy(bArr2, 0, bArr, i, bArr2.length);
        reset();
        return bArr2.length;
    }

    @Override // org.bouncycastle.crypto.Mac
    public String getAlgorithmName() {
        return "VMPC-MAC";
    }

    @Override // org.bouncycastle.crypto.Mac
    public int getMacSize() {
        return 20;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void init(CipherParameters cipherParameters) throws IllegalArgumentException {
        if (!(cipherParameters instanceof ParametersWithIV)) {
            throw new IllegalArgumentException("VMPC-MAC Init parameters must include an IV");
        }
        ParametersWithIV parametersWithIV = (ParametersWithIV) cipherParameters;
        KeyParameter keyParameter = (KeyParameter) parametersWithIV.getParameters();
        if (!(parametersWithIV.getParameters() instanceof KeyParameter)) {
            throw new IllegalArgumentException("VMPC-MAC Init parameters must include a key");
        }
        this.workingIV = parametersWithIV.getIV();
        if (this.workingIV == null || this.workingIV.length < 1 || this.workingIV.length > 768) {
            throw new IllegalArgumentException("VMPC-MAC requires 1 to 768 bytes of IV");
        }
        this.workingKey = keyParameter.getKey();
        reset();
    }

    private void initKey(byte[] bArr, byte[] bArr2) {
        this.f447s = (byte) 0;
        this.f446P = new byte[256];
        for (int i = 0; i < 256; i++) {
            this.f446P[i] = (byte) i;
        }
        for (int i2 = 0; i2 < 768; i2++) {
            this.f447s = this.f446P[(this.f447s + this.f446P[i2 & GF2Field.MASK] + bArr[i2 % bArr.length]) & GF2Field.MASK];
            byte b = this.f446P[i2 & GF2Field.MASK];
            this.f446P[i2 & GF2Field.MASK] = this.f446P[this.f447s & 255];
            this.f446P[this.f447s & 255] = b;
        }
        for (int i3 = 0; i3 < 768; i3++) {
            this.f447s = this.f446P[(this.f447s + this.f446P[i3 & GF2Field.MASK] + bArr2[i3 % bArr2.length]) & GF2Field.MASK];
            byte b2 = this.f446P[i3 & GF2Field.MASK];
            this.f446P[i3 & GF2Field.MASK] = this.f446P[this.f447s & 255];
            this.f446P[this.f447s & 255] = b2;
        }
        this.f445n = (byte) 0;
    }

    @Override // org.bouncycastle.crypto.Mac
    public void reset() {
        initKey(this.workingKey, this.workingIV);
        this.f445n = (byte) 0;
        this.f452x4 = (byte) 0;
        this.f451x3 = (byte) 0;
        this.f450x2 = (byte) 0;
        this.f449x1 = (byte) 0;
        this.f444g = (byte) 0;
        this.f448T = new byte[32];
        for (int i = 0; i < 32; i++) {
            this.f448T[i] = 0;
        }
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte b) throws IllegalStateException {
        this.f447s = this.f446P[(this.f447s + this.f446P[this.f445n & 255]) & GF2Field.MASK];
        this.f452x4 = this.f446P[(this.f452x4 + this.f451x3) & GF2Field.MASK];
        this.f451x3 = this.f446P[(this.f451x3 + this.f450x2) & GF2Field.MASK];
        this.f450x2 = this.f446P[(this.f450x2 + this.f449x1) & GF2Field.MASK];
        this.f449x1 = this.f446P[(this.f449x1 + this.f447s + ((byte) (b ^ this.f446P[(this.f446P[this.f446P[this.f447s & 255] & 255] + 1) & GF2Field.MASK]))) & GF2Field.MASK];
        this.f448T[this.f444g & 31] = (byte) (this.f448T[this.f444g & 31] ^ this.f449x1);
        this.f448T[(this.f444g + 1) & 31] = (byte) (this.f448T[(this.f444g + 1) & 31] ^ this.f450x2);
        this.f448T[(this.f444g + 2) & 31] = (byte) (this.f448T[(this.f444g + 2) & 31] ^ this.f451x3);
        this.f448T[(this.f444g + 3) & 31] = (byte) (this.f448T[(this.f444g + 3) & 31] ^ this.f452x4);
        this.f444g = (byte) ((this.f444g + 4) & 31);
        byte b2 = this.f446P[this.f445n & 255];
        this.f446P[this.f445n & 255] = this.f446P[this.f447s & 255];
        this.f446P[this.f447s & 255] = b2;
        this.f445n = (byte) ((this.f445n + 1) & GF2Field.MASK);
    }

    @Override // org.bouncycastle.crypto.Mac
    public void update(byte[] bArr, int i, int i2) throws DataLengthException, IllegalStateException {
        if (i + i2 > bArr.length) {
            throw new DataLengthException("input buffer too short");
        }
        for (int i3 = 0; i3 < i2; i3++) {
            update(bArr[i + i3]);
        }
    }
}