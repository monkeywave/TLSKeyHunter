package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class CramerShoupPublicKeyParameters extends CramerShoupKeyParameters {

    /* renamed from: c */
    private BigInteger f829c;

    /* renamed from: d */
    private BigInteger f830d;

    /* renamed from: h */
    private BigInteger f831h;

    public CramerShoupPublicKeyParameters(CramerShoupParameters cramerShoupParameters, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3) {
        super(false, cramerShoupParameters);
        this.f829c = bigInteger;
        this.f830d = bigInteger2;
        this.f831h = bigInteger3;
    }

    @Override // org.bouncycastle.crypto.params.CramerShoupKeyParameters
    public boolean equals(Object obj) {
        if (obj instanceof CramerShoupPublicKeyParameters) {
            CramerShoupPublicKeyParameters cramerShoupPublicKeyParameters = (CramerShoupPublicKeyParameters) obj;
            return cramerShoupPublicKeyParameters.getC().equals(this.f829c) && cramerShoupPublicKeyParameters.getD().equals(this.f830d) && cramerShoupPublicKeyParameters.getH().equals(this.f831h) && super.equals(obj);
        }
        return false;
    }

    public BigInteger getC() {
        return this.f829c;
    }

    public BigInteger getD() {
        return this.f830d;
    }

    public BigInteger getH() {
        return this.f831h;
    }

    @Override // org.bouncycastle.crypto.params.CramerShoupKeyParameters
    public int hashCode() {
        return ((this.f829c.hashCode() ^ this.f830d.hashCode()) ^ this.f831h.hashCode()) ^ super.hashCode();
    }
}