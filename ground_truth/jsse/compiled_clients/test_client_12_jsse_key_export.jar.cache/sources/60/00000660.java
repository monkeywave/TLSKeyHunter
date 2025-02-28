package org.bouncycastle.jcajce.interfaces;

import java.math.BigInteger;
import java.security.PublicKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/interfaces/XDHPublicKey.class */
public interface XDHPublicKey extends XDHKey, PublicKey {
    BigInteger getU();

    byte[] getUEncoding();
}