package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/CramerShoupPublicKeyParameters.class */
public class CramerShoupPublicKeyParameters extends CramerShoupKeyParameters {

    /* renamed from: c */
    private BigInteger f511c;

    /* renamed from: d */
    private BigInteger f512d;

    /* renamed from: h */
    private BigInteger f513h;

    public CramerShoupPublicKeyParameters(CramerShoupParameters cramerShoupParameters, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        super(false, cramerShoupParameters);
        this.f511c = bigInteger;
        this.f512d = bigInteger2;
        this.f513h = bigInteger3;
    }

    public BigInteger getC() {
        return this.f511c;
    }

    public BigInteger getD() {
        return this.f512d;
    }

    public BigInteger getH() {
        return this.f513h;
    }

    @Override // org.bouncycastle.crypto.params.CramerShoupKeyParameters
    public int hashCode() {
        return ((this.f511c.hashCode() ^ this.f512d.hashCode()) ^ this.f513h.hashCode()) ^ super.hashCode();
    }

    @Override // org.bouncycastle.crypto.params.CramerShoupKeyParameters
    public boolean equals(Object obj) {
        if (obj instanceof CramerShoupPublicKeyParameters) {
            CramerShoupPublicKeyParameters cramerShoupPublicKeyParameters = (CramerShoupPublicKeyParameters) obj;
            return cramerShoupPublicKeyParameters.getC().equals(this.f511c) && cramerShoupPublicKeyParameters.getD().equals(this.f512d) && cramerShoupPublicKeyParameters.getH().equals(this.f513h) && super.equals(obj);
        }
        return false;
    }
}