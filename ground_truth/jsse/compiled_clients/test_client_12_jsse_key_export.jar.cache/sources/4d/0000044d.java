package org.bouncycastle.crypto.engines;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/AESWrapEngine.class */
public class AESWrapEngine extends RFC3394WrapEngine {
    public AESWrapEngine() {
        super(new AESEngine());
    }

    public AESWrapEngine(boolean z) {
        super(new AESEngine(), z);
    }
}