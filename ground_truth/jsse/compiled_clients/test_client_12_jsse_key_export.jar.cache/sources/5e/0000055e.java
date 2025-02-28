package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.p003x9.X9ECParameters;
import org.bouncycastle.math.p010ec.ECConstants;
import org.bouncycastle.math.p010ec.ECCurve;
import org.bouncycastle.math.p010ec.ECPoint;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/ECNamedDomainParameters.class */
public class ECNamedDomainParameters extends ECDomainParameters {
    private ASN1ObjectIdentifier name;

    public ECNamedDomainParameters(ASN1ObjectIdentifier aSN1ObjectIdentifier, ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger) {
        this(aSN1ObjectIdentifier, eCCurve, eCPoint, bigInteger, ECConstants.ONE, null);
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier aSN1ObjectIdentifier, ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger, BigInteger bigInteger2) {
        this(aSN1ObjectIdentifier, eCCurve, eCPoint, bigInteger, bigInteger2, null);
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier aSN1ObjectIdentifier, ECCurve eCCurve, ECPoint eCPoint, BigInteger bigInteger, BigInteger bigInteger2, byte[] bArr) {
        super(eCCurve, eCPoint, bigInteger, bigInteger2, bArr);
        this.name = aSN1ObjectIdentifier;
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier aSN1ObjectIdentifier, ECDomainParameters eCDomainParameters) {
        super(eCDomainParameters.getCurve(), eCDomainParameters.getG(), eCDomainParameters.getN(), eCDomainParameters.getH(), eCDomainParameters.getSeed());
        this.name = aSN1ObjectIdentifier;
    }

    public ECNamedDomainParameters(ASN1ObjectIdentifier aSN1ObjectIdentifier, X9ECParameters x9ECParameters) {
        super(x9ECParameters);
        this.name = aSN1ObjectIdentifier;
    }

    public ASN1ObjectIdentifier getName() {
        return this.name;
    }
}