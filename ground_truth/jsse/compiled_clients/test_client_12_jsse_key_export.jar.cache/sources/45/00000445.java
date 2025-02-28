package org.bouncycastle.crypto.p004ec;

import org.bouncycastle.crypto.CipherParameters;

/* renamed from: org.bouncycastle.crypto.ec.ECPairTransform */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/ec/ECPairTransform.class */
public interface ECPairTransform {
    void init(CipherParameters cipherParameters);

    ECPair transform(ECPair eCPair);
}