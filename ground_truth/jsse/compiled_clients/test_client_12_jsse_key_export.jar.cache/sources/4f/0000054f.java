package org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/DHValidationParameters.class */
public class DHValidationParameters {
    private byte[] seed;
    private int counter;

    public DHValidationParameters(byte[] bArr, int i) {
        this.seed = Arrays.clone(bArr);
        this.counter = i;
    }

    public int getCounter() {
        return this.counter;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    public boolean equals(Object obj) {
        if (obj instanceof DHValidationParameters) {
            DHValidationParameters dHValidationParameters = (DHValidationParameters) obj;
            if (dHValidationParameters.counter != this.counter) {
                return false;
            }
            return Arrays.areEqual(this.seed, dHValidationParameters.seed);
        }
        return false;
    }

    public int hashCode() {
        return this.counter ^ Arrays.hashCode(this.seed);
    }
}