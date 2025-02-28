package org.bouncycastle.crypto.p004ec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.math.p010ec.ECPoint;

/* renamed from: org.bouncycastle.crypto.ec.ECDecryptor */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/ec/ECDecryptor.class */
public interface ECDecryptor {
    void init(CipherParameters cipherParameters);

    ECPoint decrypt(ECPair eCPair);
}