package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/interfaces/LMSPrivateKey.class */
public interface LMSPrivateKey extends LMSKey, PrivateKey {
    long getIndex();

    long getUsagesRemaining();

    LMSPrivateKey extractKeyShard(int i);
}