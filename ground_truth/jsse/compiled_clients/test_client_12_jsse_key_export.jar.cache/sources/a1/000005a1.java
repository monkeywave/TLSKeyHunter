package org.bouncycastle.crypto.prng;

import org.bouncycastle.crypto.prng.drbg.SP80090DRBG;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/prng/DRBGProvider.class */
interface DRBGProvider {
    String getAlgorithm();

    SP80090DRBG get(EntropySource entropySource);
}