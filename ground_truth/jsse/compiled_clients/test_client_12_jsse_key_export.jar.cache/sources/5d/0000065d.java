package org.bouncycastle.jcajce.interfaces;

import java.security.PublicKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/interfaces/EdDSAPublicKey.class */
public interface EdDSAPublicKey extends EdDSAKey, PublicKey {
    byte[] getPointEncoding();
}