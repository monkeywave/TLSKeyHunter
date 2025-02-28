package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsDSAVerifier */
/* loaded from: classes2.dex */
public class BcTlsDSAVerifier extends BcTlsDSSVerifier {
    public BcTlsDSAVerifier(BcTlsCrypto bcTlsCrypto, DSAPublicKeyParameters dSAPublicKeyParameters) {
        super(bcTlsCrypto, dSAPublicKeyParameters);
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsDSSVerifier
    protected DSA createDSAImpl() {
        return new DSASigner();
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsDSSVerifier
    protected short getSignatureAlgorithm() {
        return (short) 2;
    }
}