package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: classes2.dex */
public class CramerShoupPrivateKeyParameters extends CramerShoupKeyParameters {

    /* renamed from: pk */
    private CramerShoupPublicKeyParameters f823pk;

    /* renamed from: x1 */
    private BigInteger f824x1;

    /* renamed from: x2 */
    private BigInteger f825x2;

    /* renamed from: y1 */
    private BigInteger f826y1;

    /* renamed from: y2 */
    private BigInteger f827y2;

    /* renamed from: z */
    private BigInteger f828z;

    public CramerShoupPrivateKeyParameters(CramerShoupParameters cramerShoupParameters, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, BigInteger bigInteger5) {
        super(true, cramerShoupParameters);
        this.f824x1 = bigInteger;
        this.f825x2 = bigInteger2;
        this.f826y1 = bigInteger3;
        this.f827y2 = bigInteger4;
        this.f828z = bigInteger5;
    }

    @Override // org.bouncycastle.crypto.params.CramerShoupKeyParameters
    public boolean equals(Object obj) {
        if (obj instanceof CramerShoupPrivateKeyParameters) {
            CramerShoupPrivateKeyParameters cramerShoupPrivateKeyParameters = (CramerShoupPrivateKeyParameters) obj;
            return cramerShoupPrivateKeyParameters.getX1().equals(this.f824x1) && cramerShoupPrivateKeyParameters.getX2().equals(this.f825x2) && cramerShoupPrivateKeyParameters.getY1().equals(this.f826y1) && cramerShoupPrivateKeyParameters.getY2().equals(this.f827y2) && cramerShoupPrivateKeyParameters.getZ().equals(this.f828z) && super.equals(obj);
        }
        return false;
    }

    public CramerShoupPublicKeyParameters getPk() {
        return this.f823pk;
    }

    public BigInteger getX1() {
        return this.f824x1;
    }

    public BigInteger getX2() {
        return this.f825x2;
    }

    public BigInteger getY1() {
        return this.f826y1;
    }

    public BigInteger getY2() {
        return this.f827y2;
    }

    public BigInteger getZ() {
        return this.f828z;
    }

    @Override // org.bouncycastle.crypto.params.CramerShoupKeyParameters
    public int hashCode() {
        return ((((this.f824x1.hashCode() ^ this.f825x2.hashCode()) ^ this.f826y1.hashCode()) ^ this.f827y2.hashCode()) ^ this.f828z.hashCode()) ^ super.hashCode();
    }

    public void setPk(CramerShoupPublicKeyParameters cramerShoupPublicKeyParameters) {
        this.f823pk = cramerShoupPublicKeyParameters;
    }
}