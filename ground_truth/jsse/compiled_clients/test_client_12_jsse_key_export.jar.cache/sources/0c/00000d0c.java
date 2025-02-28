package org.bouncycastle.math.field;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/field/FiniteField.class */
public interface FiniteField {
    BigInteger getCharacteristic();

    int getDimension();
}