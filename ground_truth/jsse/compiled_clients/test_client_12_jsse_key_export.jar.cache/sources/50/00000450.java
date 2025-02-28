package org.bouncycastle.crypto.engines;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/ARIAWrapEngine.class */
public class ARIAWrapEngine extends RFC3394WrapEngine {
    public ARIAWrapEngine() {
        super(new ARIAEngine());
    }

    public ARIAWrapEngine(boolean z) {
        super(new ARIAEngine(), z);
    }
}