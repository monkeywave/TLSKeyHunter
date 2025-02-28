package org.bouncycastle.crypto.p004ec;

import java.math.BigInteger;

/* renamed from: org.bouncycastle.crypto.ec.ECPairFactorTransform */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/ec/ECPairFactorTransform.class */
public interface ECPairFactorTransform extends ECPairTransform {
    BigInteger getTransformValue();
}