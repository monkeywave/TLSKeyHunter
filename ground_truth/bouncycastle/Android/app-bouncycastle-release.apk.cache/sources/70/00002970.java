package org.bouncycastle.pqc.crypto.crystals.dilithium;

import org.bouncycastle.util.Arrays;

/* loaded from: classes2.dex */
public class DilithiumPublicKeyParameters extends DilithiumKeyParameters {
    final byte[] rho;

    /* renamed from: t1 */
    final byte[] f1229t1;

    public DilithiumPublicKeyParameters(DilithiumParameters dilithiumParameters, byte[] bArr) {
        super(false, dilithiumParameters);
        this.rho = Arrays.copyOfRange(bArr, 0, 32);
        this.f1229t1 = Arrays.copyOfRange(bArr, 32, bArr.length);
    }

    public DilithiumPublicKeyParameters(DilithiumParameters dilithiumParameters, byte[] bArr, byte[] bArr2) {
        super(false, dilithiumParameters);
        this.rho = Arrays.clone(bArr);
        this.f1229t1 = Arrays.clone(bArr2);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static byte[] getEncoded(byte[] bArr, byte[] bArr2) {
        return Arrays.concatenate(bArr, bArr2);
    }

    public byte[] getEncoded() {
        return getEncoded(this.rho, this.f1229t1);
    }

    public byte[] getRho() {
        return Arrays.clone(this.rho);
    }

    public byte[] getT1() {
        return Arrays.clone(this.f1229t1);
    }
}