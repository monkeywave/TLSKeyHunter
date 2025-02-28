package org.bouncycastle.crypto.engines;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/CamelliaWrapEngine.class */
public class CamelliaWrapEngine extends RFC3394WrapEngine {
    public CamelliaWrapEngine() {
        super(new CamelliaEngine());
    }
}