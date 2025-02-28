package org.bouncycastle.crypto.p004ec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.math.p010ec.ECPoint;

/* renamed from: org.bouncycastle.crypto.ec.ECEncryptor */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/ec/ECEncryptor.class */
public interface ECEncryptor {
    void init(CipherParameters cipherParameters);

    ECPair encrypt(ECPoint eCPoint);
}