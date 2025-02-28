package org.bouncycastle.pqc.jcajce.interfaces;

import java.security.PrivateKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/pqc/jcajce/interfaces/XMSSMTPrivateKey.class */
public interface XMSSMTPrivateKey extends XMSSMTKey, PrivateKey {
    long getIndex();

    long getUsagesRemaining();

    XMSSMTPrivateKey extractKeyShard(int i);
}