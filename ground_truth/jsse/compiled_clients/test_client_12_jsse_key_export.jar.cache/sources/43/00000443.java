package org.bouncycastle.crypto.p004ec;

import org.bouncycastle.math.p010ec.ECPoint;

/* renamed from: org.bouncycastle.crypto.ec.ECPair */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/ec/ECPair.class */
public class ECPair {

    /* renamed from: x */
    private final ECPoint f275x;

    /* renamed from: y */
    private final ECPoint f276y;

    public ECPair(ECPoint eCPoint, ECPoint eCPoint2) {
        this.f275x = eCPoint;
        this.f276y = eCPoint2;
    }

    public ECPoint getX() {
        return this.f275x;
    }

    public ECPoint getY() {
        return this.f276y;
    }

    public boolean equals(ECPair eCPair) {
        return eCPair.getX().equals(getX()) && eCPair.getY().equals(getY());
    }

    public boolean equals(Object obj) {
        if (obj instanceof ECPair) {
            return equals((ECPair) obj);
        }
        return false;
    }

    public int hashCode() {
        return this.f275x.hashCode() + (37 * this.f276y.hashCode());
    }
}