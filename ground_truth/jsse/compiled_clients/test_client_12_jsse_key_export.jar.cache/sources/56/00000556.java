package org.bouncycastle.crypto.params;

import org.bouncycastle.util.Arrays;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/DSAValidationParameters.class */
public class DSAValidationParameters {
    private int usageIndex;
    private byte[] seed;
    private int counter;

    public DSAValidationParameters(byte[] bArr, int i) {
        this(bArr, i, -1);
    }

    public DSAValidationParameters(byte[] bArr, int i, int i2) {
        this.seed = Arrays.clone(bArr);
        this.counter = i;
        this.usageIndex = i2;
    }

    public int getCounter() {
        return this.counter;
    }

    public byte[] getSeed() {
        return Arrays.clone(this.seed);
    }

    public int getUsageIndex() {
        return this.usageIndex;
    }

    public int hashCode() {
        return this.counter ^ Arrays.hashCode(this.seed);
    }

    public boolean equals(Object obj) {
        if (obj instanceof DSAValidationParameters) {
            DSAValidationParameters dSAValidationParameters = (DSAValidationParameters) obj;
            if (dSAValidationParameters.counter != this.counter) {
                return false;
            }
            return Arrays.areEqual(this.seed, dSAValidationParameters.seed);
        }
        return false;
    }
}