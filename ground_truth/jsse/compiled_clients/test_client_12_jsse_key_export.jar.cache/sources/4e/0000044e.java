package org.bouncycastle.crypto.engines;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/AESWrapPadEngine.class */
public class AESWrapPadEngine extends RFC5649WrapEngine {
    public AESWrapPadEngine() {
        super(new AESEngine());
    }
}