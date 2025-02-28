package org.bouncycastle.crypto.params;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/Ed448KeyGenerationParameters.class */
public class Ed448KeyGenerationParameters extends KeyGenerationParameters {
    public Ed448KeyGenerationParameters(SecureRandom secureRandom) {
        super(secureRandom, 448);
    }
}