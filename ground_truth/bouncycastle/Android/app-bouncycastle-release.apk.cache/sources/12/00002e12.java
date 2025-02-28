package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsECDSASigner */
/* loaded from: classes2.dex */
public class BcTlsECDSASigner extends BcTlsDSSSigner {
    public BcTlsECDSASigner(BcTlsCrypto bcTlsCrypto, ECPrivateKeyParameters eCPrivateKeyParameters) {
        super(bcTlsCrypto, eCPrivateKeyParameters);
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsDSSSigner
    protected DSA createDSAImpl(int i) {
        return new ECDSASigner(new HMacDSAKCalculator(this.crypto.createDigest(i)));
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsDSSSigner
    protected short getSignatureAlgorithm() {
        return (short) 3;
    }
}