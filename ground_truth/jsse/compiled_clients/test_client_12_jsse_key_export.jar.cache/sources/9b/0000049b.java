package org.bouncycastle.crypto.engines;

import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/engines/Zuc128Engine.class */
public final class Zuc128Engine extends Zuc128CoreEngine {
    public Zuc128Engine() {
    }

    private Zuc128Engine(Zuc128Engine zuc128Engine) {
        super(zuc128Engine);
    }

    @Override // org.bouncycastle.crypto.engines.Zuc128CoreEngine, org.bouncycastle.util.Memoable
    public Memoable copy() {
        return new Zuc128Engine(this);
    }
}