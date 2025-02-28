package org.bouncycastle.crypto.params;

import org.bouncycastle.math.p010ec.ECPoint;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ECPublicKeyParameters.class */
public class ECPublicKeyParameters extends ECKeyParameters {

    /* renamed from: q */
    private final ECPoint f533q;

    public ECPublicKeyParameters(ECPoint eCPoint, ECDomainParameters eCDomainParameters) {
        super(false, eCDomainParameters);
        this.f533q = eCDomainParameters.validatePublicPoint(eCPoint);
    }

    public ECPoint getQ() {
        return this.f533q;
    }
}