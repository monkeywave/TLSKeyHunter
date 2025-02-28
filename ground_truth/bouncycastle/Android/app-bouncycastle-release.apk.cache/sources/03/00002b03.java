package org.bouncycastle.pqc.crypto.xmss;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: classes2.dex */
public final class XMSSKeyGenerationParameters extends KeyGenerationParameters {
    private final XMSSParameters xmssParameters;

    public XMSSKeyGenerationParameters(XMSSParameters xMSSParameters, SecureRandom secureRandom) {
        super(secureRandom, -1);
        this.xmssParameters = xMSSParameters;
    }

    public XMSSParameters getParameters() {
        return this.xmssParameters;
    }
}