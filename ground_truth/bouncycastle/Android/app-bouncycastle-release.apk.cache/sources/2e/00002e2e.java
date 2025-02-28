package org.bouncycastle.tls.crypto.impl.p018bc;

import org.bouncycastle.tls.crypto.TlsAgreement;
import org.bouncycastle.tls.crypto.TlsECDomain;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcX448Domain */
/* loaded from: classes2.dex */
public class BcX448Domain implements TlsECDomain {
    protected final BcTlsCrypto crypto;

    public BcX448Domain(BcTlsCrypto bcTlsCrypto) {
        this.crypto = bcTlsCrypto;
    }

    @Override // org.bouncycastle.tls.crypto.TlsECDomain
    public TlsAgreement createECDH() {
        return new BcX448(this.crypto);
    }
}