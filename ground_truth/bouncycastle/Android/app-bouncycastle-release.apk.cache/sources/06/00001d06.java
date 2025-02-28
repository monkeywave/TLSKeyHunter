package org.bouncycastle.crypto.p010ec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.math.p016ec.ECPoint;

/* renamed from: org.bouncycastle.crypto.ec.ECDecryptor */
/* loaded from: classes2.dex */
public interface ECDecryptor {
    ECPoint decrypt(ECPair eCPair);

    void init(CipherParameters cipherParameters);
}