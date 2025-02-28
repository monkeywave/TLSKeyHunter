package org.bouncycastle.pqc.crypto.cmce;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class CMCEPrivateKeyParameters extends CMCEKeyParameters {
    private final byte[] privateKey;

    public CMCEPrivateKeyParameters(CMCEParameters cMCEParameters, byte[] bArr) {
        super(true, cMCEParameters);
        this.privateKey = Arrays.clone(bArr);
    }

    public CMCEPrivateKeyParameters(CMCEParameters cMCEParameters, byte[] bArr, byte[] bArr2, byte[] bArr3, byte[] bArr4, byte[] bArr5) {
        super(true, cMCEParameters);
        byte[] bArr6 = new byte[bArr.length + bArr2.length + bArr3.length + bArr4.length + bArr5.length];
        this.privateKey = bArr6;
        System.arraycopy(bArr, 0, bArr6, 0, bArr.length);
        int length = bArr.length;
        System.arraycopy(bArr2, 0, bArr6, length, bArr2.length);
        int length2 = length + bArr2.length;
        System.arraycopy(bArr3, 0, bArr6, length2, bArr3.length);
        int length3 = length2 + bArr3.length;
        System.arraycopy(bArr4, 0, bArr6, length3, bArr4.length);
        System.arraycopy(bArr5, 0, bArr6, length3 + bArr4.length, bArr5.length);
    }

    public byte[] getAlpha() {
        return Arrays.copyOfRange(this.privateKey, (getParameters().getT() * 2) + 40, this.privateKey.length - 32);
    }

    public byte[] getC() {
        return Arrays.copyOfRange(this.privateKey, 32, 40);
    }

    public byte[] getDelta() {
        return Arrays.copyOfRange(this.privateKey, 0, 32);
    }

    public byte[] getEncoded() {
        return Arrays.clone(this.privateKey);
    }

    public byte[] getG() {
        return Arrays.copyOfRange(this.privateKey, 40, (getParameters().getT() * 2) + 40);
    }

    public byte[] getPrivateKey() {
        return Arrays.clone(this.privateKey);
    }

    public byte[] getS() {
        byte[] bArr = this.privateKey;
        return Arrays.copyOfRange(bArr, bArr.length - 32, bArr.length);
    }

    public byte[] reconstructPublicKey() {
        CMCEEngine engine = getParameters().getEngine();
        byte[] bArr = new byte[engine.getPublicKeySize()];
        engine.generate_public_key_from_private_key(this.privateKey);
        return bArr;
    }
}