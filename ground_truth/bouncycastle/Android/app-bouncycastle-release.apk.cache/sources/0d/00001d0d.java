package org.bouncycastle.crypto.p010ec;

import org.bouncycastle.math.p016ec.ECPoint;

/* renamed from: org.bouncycastle.crypto.ec.ECPair */
/* loaded from: classes2.dex */
public class ECPair {

    /* renamed from: x */
    private final ECPoint f551x;

    /* renamed from: y */
    private final ECPoint f552y;

    public ECPair(ECPoint eCPoint, ECPoint eCPoint2) {
        this.f551x = eCPoint;
        this.f552y = eCPoint2;
    }

    public boolean equals(Object obj) {
        if (obj instanceof ECPair) {
            return equals((ECPair) obj);
        }
        return false;
    }

    public boolean equals(ECPair eCPair) {
        return eCPair.getX().equals(getX()) && eCPair.getY().equals(getY());
    }

    public ECPoint getX() {
        return this.f551x;
    }

    public ECPoint getY() {
        return this.f552y;
    }

    public int hashCode() {
        return this.f551x.hashCode() + (this.f552y.hashCode() * 37);
    }
}