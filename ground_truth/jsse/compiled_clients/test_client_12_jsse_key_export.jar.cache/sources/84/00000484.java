package org.bouncycastle.crypto.engines;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/SEEDWrapEngine.class */
public class SEEDWrapEngine extends RFC3394WrapEngine {
    public SEEDWrapEngine() {
        super(new SEEDEngine());
    }
}