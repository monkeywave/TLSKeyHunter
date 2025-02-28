package org.bouncycastle.jce.interfaces;

import java.math.BigInteger;
import javax.crypto.interfaces.DHPublicKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/interfaces/ElGamalPublicKey.class */
public interface ElGamalPublicKey extends ElGamalKey, DHPublicKey {
    BigInteger getY();
}