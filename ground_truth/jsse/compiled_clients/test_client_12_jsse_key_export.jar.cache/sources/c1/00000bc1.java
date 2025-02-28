package org.bouncycastle.jce.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/interfaces/GOST3410PublicKey.class */
public interface GOST3410PublicKey extends GOST3410Key, PublicKey {
    BigInteger getY();
}