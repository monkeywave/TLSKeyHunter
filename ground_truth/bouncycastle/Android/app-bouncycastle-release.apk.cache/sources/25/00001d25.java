package org.bouncycastle.crypto.engines;

/* loaded from: classes2.dex */
public class CamelliaWrapEngine extends RFC3394WrapEngine {
    public CamelliaWrapEngine() {
        super(new CamelliaEngine());
    }
}