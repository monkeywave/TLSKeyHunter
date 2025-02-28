package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/interfaces/NHPrivateKey.class */
public interface NHPrivateKey extends NHKey, PrivateKey {
    short[] getSecretData();
}