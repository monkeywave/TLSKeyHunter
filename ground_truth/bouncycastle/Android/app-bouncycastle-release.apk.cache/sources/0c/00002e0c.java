package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.crypto.DSA;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.signers.DSASigner;
import org.bouncycastle.crypto.signers.HMacDSAKCalculator;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsDSASigner */
/* loaded from: classes2.dex */
public class BcTlsDSASigner extends BcTlsDSSSigner {
    public BcTlsDSASigner(BcTlsCrypto bcTlsCrypto, DSAPrivateKeyParameters dSAPrivateKeyParameters) {
        super(bcTlsCrypto, dSAPrivateKeyParameters);
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsDSSSigner
    protected DSA createDSAImpl(int i) {
        return new DSASigner(new HMacDSAKCalculator(this.crypto.createDigest(i)));
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsDSSSigner
    protected short getSignatureAlgorithm() {
        return (short) 2;
    }
}