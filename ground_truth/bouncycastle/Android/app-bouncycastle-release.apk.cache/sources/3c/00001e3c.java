package org.bouncycastle.crypto.params;

import java.math.BigInteger;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.util.Memoable;

/* loaded from: classes2.dex */
public class CramerShoupParameters implements CipherParameters {

    /* renamed from: H */
    private Digest f819H;

    /* renamed from: g1 */
    private BigInteger f820g1;

    /* renamed from: g2 */
    private BigInteger f821g2;

    /* renamed from: p */
    private BigInteger f822p;

    public CramerShoupParameters(BigInteger bigInteger, BigInteger bigInteger2, BigInteger bigInteger3, Digest digest) {
        this.f822p = bigInteger;
        this.f820g1 = bigInteger2;
        this.f821g2 = bigInteger3;
        Digest digest2 = (Digest) ((Memoable) digest).copy();
        this.f819H = digest2;
        digest2.reset();
    }

    public boolean equals(Object obj) {
        if (obj instanceof CramerShoupParameters) {
            CramerShoupParameters cramerShoupParameters = (CramerShoupParameters) obj;
            return cramerShoupParameters.getP().equals(this.f822p) && cramerShoupParameters.getG1().equals(this.f820g1) && cramerShoupParameters.getG2().equals(this.f821g2);
        }
        return false;
    }

    public BigInteger getG1() {
        return this.f820g1;
    }

    public BigInteger getG2() {
        return this.f821g2;
    }

    public Digest getH() {
        return (Digest) ((Memoable) this.f819H).copy();
    }

    public BigInteger getP() {
        return this.f822p;
    }

    public int hashCode() {
        return (getP().hashCode() ^ getG1().hashCode()) ^ getG2().hashCode();
    }
}