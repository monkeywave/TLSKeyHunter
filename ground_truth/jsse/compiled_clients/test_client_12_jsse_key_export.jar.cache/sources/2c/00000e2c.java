package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/interfaces/XMSSPrivateKey.class */
public interface XMSSPrivateKey extends XMSSKey, PrivateKey {
    long getIndex();

    long getUsagesRemaining();

    XMSSPrivateKey extractKeyShard(int i);
}