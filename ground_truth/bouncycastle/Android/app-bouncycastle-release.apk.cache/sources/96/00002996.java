package org.bouncycastle.pqc.crypto.frodo;

import org.bouncycastle.crypto.EncapsulatedSecretExtractor;

/* loaded from: classes2.dex */
public class FrodoKEMExtractor implements EncapsulatedSecretExtractor {
    private FrodoEngine engine;
    private FrodoKeyParameters key;

    public FrodoKEMExtractor(FrodoKeyParameters frodoKeyParameters) {
        this.key = frodoKeyParameters;
        initCipher(frodoKeyParameters.getParameters());
    }

    private void initCipher(FrodoParameters frodoParameters) {
        this.engine = frodoParameters.getEngine();
    }

    @Override // org.bouncycastle.crypto.EncapsulatedSecretExtractor
    public byte[] extractSecret(byte[] bArr) {
        byte[] bArr2 = new byte[this.engine.getSessionKeySize()];
        this.engine.kem_dec(bArr2, bArr, ((FrodoPrivateKeyParameters) this.key).getPrivateKey());
        return bArr2;
    }

    @Override // org.bouncycastle.crypto.EncapsulatedSecretExtractor
    public int getEncapsulationLength() {
        return this.engine.getCipherTextSize();
    }
}