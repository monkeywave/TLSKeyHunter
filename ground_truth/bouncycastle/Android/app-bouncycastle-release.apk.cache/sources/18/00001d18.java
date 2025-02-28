package org.bouncycastle.crypto.engines;

/* loaded from: classes2.dex */
public class AESWrapPadEngine extends RFC5649WrapEngine {
    public AESWrapPadEngine() {
        super(AESEngine.newInstance());
    }
}