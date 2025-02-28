package org.bouncycastle.crypto.p010ec;

import org.bouncycastle.crypto.CipherParameters;

/* renamed from: org.bouncycastle.crypto.ec.ECPairTransform */
/* loaded from: classes2.dex */
public interface ECPairTransform {
    void init(CipherParameters cipherParameters);

    ECPair transform(ECPair eCPair);
}