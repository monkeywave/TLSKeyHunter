package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

/* loaded from: classes2.dex */
public class JcaTlsEd448Signer extends JcaTlsEdDSASigner {
    public JcaTlsEd448Signer(JcaTlsCrypto jcaTlsCrypto, PrivateKey privateKey) {
        super(jcaTlsCrypto, privateKey, (short) 8, EdDSAParameterSpec.Ed448);
    }
}