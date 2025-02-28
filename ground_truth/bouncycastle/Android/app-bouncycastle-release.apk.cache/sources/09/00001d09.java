package org.bouncycastle.crypto.p010ec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.math.p016ec.ECPoint;

/* renamed from: org.bouncycastle.crypto.ec.ECEncryptor */
/* loaded from: classes2.dex */
public interface ECEncryptor {
    ECPair encrypt(ECPoint eCPoint);

    void init(CipherParameters cipherParameters);
}