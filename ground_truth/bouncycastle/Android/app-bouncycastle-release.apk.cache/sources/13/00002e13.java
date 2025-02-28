package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsECDSAVerifier */
/* loaded from: classes2.dex */
public class BcTlsECDSAVerifier extends BcTlsDSSVerifier {
    public BcTlsECDSAVerifier(BcTlsCrypto bcTlsCrypto, ECPublicKeyParameters eCPublicKeyParameters) {
        super(bcTlsCrypto, eCPublicKeyParameters);
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsDSSVerifier
    protected DSA createDSAImpl() {
        return new ECDSASigner();
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsDSSVerifier
    protected short getSignatureAlgorithm() {
        return (short) 3;
    }
}