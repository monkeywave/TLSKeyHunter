package org.bouncycastle.jce.interfaces;

import java.security.PublicKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/interfaces/MQVPublicKey.class */
public interface MQVPublicKey extends PublicKey {
    PublicKey getStaticKey();

    PublicKey getEphemeralKey();
}