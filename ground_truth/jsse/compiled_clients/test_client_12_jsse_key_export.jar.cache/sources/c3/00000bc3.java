package org.bouncycastle.jce.interfaces;

import java.security.PrivateKey;
import java.security.PublicKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/interfaces/MQVPrivateKey.class */
public interface MQVPrivateKey extends PrivateKey {
    PrivateKey getStaticPrivateKey();

    PrivateKey getEphemeralPrivateKey();

    PublicKey getEphemeralPublicKey();
}