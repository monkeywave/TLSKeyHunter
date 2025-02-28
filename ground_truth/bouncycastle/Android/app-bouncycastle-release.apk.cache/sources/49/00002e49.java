package org.bouncycastle.tls.crypto.impl.jcajce;

import java.security.PrivateKey;
import org.bouncycastle.jcajce.spec.EdDSAParameterSpec;

/* loaded from: classes2.dex */
public class JcaTlsEd25519Signer extends JcaTlsEdDSASigner {
    public JcaTlsEd25519Signer(JcaTlsCrypto jcaTlsCrypto, PrivateKey privateKey) {
        super(jcaTlsCrypto, privateKey, (short) 7, EdDSAParameterSpec.Ed25519);
    }
}