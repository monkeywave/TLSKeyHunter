package org.bouncycastle.math.field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/field/ExtensionField.class */
public interface ExtensionField extends FiniteField {
    FiniteField getSubfield();

    int getDegree();
}