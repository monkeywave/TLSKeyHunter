package org.bouncycastle.crypto.params;

import java.security.SecureRandom;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.pqc.crypto.rainbow.util.GF2Field;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/X25519KeyGenerationParameters.class */
public class X25519KeyGenerationParameters extends KeyGenerationParameters {
    public X25519KeyGenerationParameters(SecureRandom secureRandom) {
        super(secureRandom, GF2Field.MASK);
    }
}