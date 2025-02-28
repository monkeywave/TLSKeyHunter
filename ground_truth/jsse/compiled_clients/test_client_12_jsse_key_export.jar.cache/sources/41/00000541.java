package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Memoable;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/CramerShoupParameters.class */
public class CramerShoupParameters implements CipherParameters {

    /* renamed from: p */
    private BigInteger f501p;

    /* renamed from: g1 */
    private BigInteger f502g1;

    /* renamed from: g2 */
    private BigInteger f503g2;

    /* renamed from: H */
    private Digest f504H;

    public CramerShoupParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, Digest digest) {
        this.f501p = bigInteger;
        this.f502g1 = bigInteger2;
        this.f503g2 = bigInteger3;
        this.f504H = (Digest) ((Memoable) digest).copy();
        this.f504H.reset();
    }

    public boolean equals(Object obj) {
        if (obj instanceof CramerShoupParameters) {
            CramerShoupParameters cramerShoupParameters = (CramerShoupParameters) obj;
            return cramerShoupParameters.getP().equals(this.f501p) && cramerShoupParameters.getG1().equals(this.f502g1) && cramerShoupParameters.getG2().equals(this.f503g2);
        }
        return false;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getG1().hashCode()) ^ getG2().hashCode();
    }

    public BigInteger getG1() {
        return this.f502g1;
    }

    public BigInteger getG2() {
        return this.f503g2;
    }

    public BigInteger getP() {
        return this.f501p;
    }

    public Digest getH() {
        return (Digest) ((Memoable) this.f504H).copy();
    }
}