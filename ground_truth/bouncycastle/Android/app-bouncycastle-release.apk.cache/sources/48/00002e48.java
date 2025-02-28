package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PublicKey;

/* loaded from: classes2.dex */
public class JcaTlsECDSAVerifier extends JcaTlsDSSVerifier {
    public JcaTlsECDSAVerifier(JcaTlsCrypto jcaTlsCrypto, PublicKey publicKey) {
        super(jcaTlsCrypto, publicKey, (short) 3, "NoneWithECDSA");
    }
}