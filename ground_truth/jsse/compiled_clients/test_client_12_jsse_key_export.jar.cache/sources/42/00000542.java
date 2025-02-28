package org.bouncycastle.crypto.params;

import java.math.BigInteger;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/CramerShoupPrivateKeyParameters.class */
public class CramerShoupPrivateKeyParameters extends CramerShoupKeyParameters {

    /* renamed from: x1 */
    private BigInteger f505x1;

    /* renamed from: x2 */
    private BigInteger f506x2;

    /* renamed from: y1 */
    private BigInteger f507y1;

    /* renamed from: y2 */
    private BigInteger f508y2;

    /* renamed from: z */
    private BigInteger f509z;

    /* renamed from: pk */
    private CramerShoupPublicKeyParameters f510pk;

    public CramerShoupPrivateKeyParameters(CramerShoupParameters cramerShoupParameters, BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, BigInteger bigInteger4, BigInteger bigInteger5) {
        super(true, cramerShoupParameters);
        this.f505x1 = bigInteger;
        this.f506x2 = bigInteger2;
        this.f507y1 = bigInteger3;
        this.f508y2 = bigInteger4;
        this.f509z = bigInteger5;
    }

    public BigInteger getX1() {
        return this.f505x1;
    }

    public BigInteger getX2() {
        return this.f506x2;
    }

    public BigInteger getY1() {
        return this.f507y1;
    }

    public BigInteger getY2() {
        return this.f508y2;
    }

    public BigInteger getZ() {
        return this.f509z;
    }

    public void setPk(CramerShoupPublicKeyParameters cramerShoupPublicKeyParameters) {
        this.f510pk = cramerShoupPublicKeyParameters;
    }

    public CramerShoupPublicKeyParameters getPk() {
        return this.f510pk;
    }

    @Override // org.bouncycastle.crypto.params.CramerShoupKeyParameters
    public int hashCode() {
        return ((((this.f505x1.hashCode() ^ this.f506x2.hashCode()) ^ this.f507y1.hashCode()) ^ this.f508y2.hashCode()) ^ this.f509z.hashCode()) ^ super.hashCode();
    }

    @Override // org.bouncycastle.crypto.params.CramerShoupKeyParameters
    public boolean equals(Object obj) {
        if (obj instanceof CramerShoupPrivateKeyParameters) {
            CramerShoupPrivateKeyParameters cramerShoupPrivateKeyParameters = (CramerShoupPrivateKeyParameters) obj;
            return cramerShoupPrivateKeyParameters.getX1().equals(this.f505x1) && cramerShoupPrivateKeyParameters.getX2().equals(this.f506x2) && cramerShoupPrivateKeyParameters.getY1().equals(this.f507y1) && cramerShoupPrivateKeyParameters.getY2().equals(this.f508y2) && cramerShoupPrivateKeyParameters.getZ().equals(this.f509z) && super.equals(obj);
        }
        return false;
    }
}