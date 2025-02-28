package org.bouncycastle.crypto.params;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/FPEParameters.class */
public final class FPEParameters implements CipherParameters {
    private final KeyParameter key;
    private final int radix;
    private final byte[] tweak;
    private final boolean useInverse;

    public FPEParameters(KeyParameter keyParameter, int i, byte[] bArr) {
        this(keyParameter, i, bArr, false);
    }

    public FPEParameters(KeyParameter keyParameter, int i, byte[] bArr, boolean z) {
        this.key = keyParameter;
        this.radix = i;
        this.tweak = Arrays.clone(bArr);
        this.useInverse = z;
    }

    public KeyParameter getKey() {
        return this.key;
    }

    public int getRadix() {
        return this.radix;
    }

    public byte[] getTweak() {
        return Arrays.clone(this.tweak);
    }

    public boolean isUsingInverseFunction() {
        return this.useInverse;
    }
}