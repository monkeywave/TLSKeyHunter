package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.DerivationParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/KDFFeedbackParameters.class */
public final class KDFFeedbackParameters implements DerivationParameters {
    private static final int UNUSED_R = -1;

    /* renamed from: ki */
    private final byte[] f551ki;

    /* renamed from: iv */
    private final byte[] f552iv;
    private final boolean useCounter;

    /* renamed from: r */
    private final int f553r;
    private final byte[] fixedInputData;

    private KDFFeedbackParameters(byte[] bArr, byte[] bArr2, byte[] bArr3, int i, boolean z) {
        if (bArr == null) {
            throw new IllegalArgumentException("A KDF requires Ki (a seed) as input");
        }
        this.f551ki = Arrays.clone(bArr);
        if (bArr3 == null) {
            this.fixedInputData = new byte[0];
        } else {
            this.fixedInputData = Arrays.clone(bArr3);
        }
        this.f553r = i;
        if (bArr2 == null) {
            this.f552iv = new byte[0];
        } else {
            this.f552iv = Arrays.clone(bArr2);
        }
        this.useCounter = z;
    }

    public static KDFFeedbackParameters createWithCounter(byte[] bArr, byte[] bArr2, byte[] bArr3, int i) {
        if (i == 8 || i == 16 || i == 24 || i == 32) {
            return new KDFFeedbackParameters(bArr, bArr2, bArr3, i, true);
        }
        throw new IllegalArgumentException("Length of counter should be 8, 16, 24 or 32");
    }

    public static KDFFeedbackParameters createWithoutCounter(byte[] bArr, byte[] bArr2, byte[] bArr3) {
        return new KDFFeedbackParameters(bArr, bArr2, bArr3, UNUSED_R, false);
    }

    public byte[] getKI() {
        return this.f551ki;
    }

    public byte[] getIV() {
        return this.f552iv;
    }

    public boolean useCounter() {
        return this.useCounter;
    }

    public int getR() {
        return this.f553r;
    }

    public byte[] getFixedInputData() {
        return Arrays.clone(this.fixedInputData);
    }
}