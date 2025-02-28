package org.bouncycastle.math.field;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/field/PrimeField.class */
class PrimeField implements FiniteField {
    protected final BigInteger characteristic;

    /* JADX INFO: Access modifiers changed from: package-private */
    public PrimeField(BigInteger bigInteger) {
        this.characteristic = bigInteger;
    }

    @Override // org.bouncycastle.math.field.FiniteField
    public BigInteger getCharacteristic() {
        return this.characteristic;
    }

    @Override // org.bouncycastle.math.field.FiniteField
    public int getDimension() {
        return 1;
    }

    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof PrimeField) {
            return this.characteristic.equals(((PrimeField) obj).characteristic);
        }
        return false;
    }

    public int hashCode() {
        return this.characteristic.hashCode();
    }
}