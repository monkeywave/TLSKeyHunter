package org.bouncycastle.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/interfaces/EdDSAPrivateKey.class */
public interface EdDSAPrivateKey extends EdDSAKey, PrivateKey {
    EdDSAPublicKey getPublicKey();
}