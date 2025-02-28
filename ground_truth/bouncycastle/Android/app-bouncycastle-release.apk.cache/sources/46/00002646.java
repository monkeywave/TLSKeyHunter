package org.bouncycastle.jsse;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/* loaded from: classes2.dex */
public interface BCX509Key {
    X509Certificate[] getCertificateChain();

    String getKeyType();

    PrivateKey getPrivateKey();
}