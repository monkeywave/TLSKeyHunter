package org.bouncycastle.jce.interfaces;

import java.math.BigInteger;
import java.security.PrivateKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/interfaces/ECPrivateKey.class */
public interface ECPrivateKey extends ECKey, PrivateKey {
    BigInteger getD();
}