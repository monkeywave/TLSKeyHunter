package org.bouncycastle.crypto.engines;

/* loaded from: classes2.dex */
public class ARIAWrapPadEngine extends RFC5649WrapEngine {
    public ARIAWrapPadEngine() {
        super(new ARIAEngine());
    }
}