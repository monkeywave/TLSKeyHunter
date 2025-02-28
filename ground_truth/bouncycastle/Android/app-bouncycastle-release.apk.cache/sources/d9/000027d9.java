package org.bouncycastle.math.field;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public interface FiniteField {
    BigInteger getCharacteristic();

    int getDimension();
}