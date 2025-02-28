package org.bouncycastle.tls;

import org.bouncycastle.tls.crypto.TlsSecret;

/* loaded from: classes2.dex */
public interface TlsPSK {
    byte[] getIdentity();

    TlsSecret getKey();

    int getPRFAlgorithm();
}