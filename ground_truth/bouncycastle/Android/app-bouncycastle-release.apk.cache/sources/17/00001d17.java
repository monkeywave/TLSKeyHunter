package org.bouncycastle.crypto.engines;

/* loaded from: classes2.dex */
public class AESWrapEngine extends RFC3394WrapEngine {
    public AESWrapEngine() {
        super(AESEngine.newInstance());
    }

    public AESWrapEngine(boolean z) {
        super(AESEngine.newInstance(), z);
    }
}