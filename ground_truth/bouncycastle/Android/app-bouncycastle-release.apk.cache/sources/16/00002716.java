package org.bouncycastle.math.p016ec;

/* renamed from: org.bouncycastle.math.ec.WNafPreCompInfo */
/* loaded from: classes2.dex */
public class WNafPreCompInfo implements PreCompInfo {
    volatile int promotionCountdown = 4;
    protected int confWidth = -1;
    protected ECPoint[] preComp = null;
    protected ECPoint[] preCompNeg = null;
    protected ECPoint twice = null;
    protected int width = -1;

    /* JADX INFO: Access modifiers changed from: package-private */
    public int decrementPromotionCountdown() {
        int i = this.promotionCountdown;
        if (i > 0) {
            int i2 = i - 1;
            this.promotionCountdown = i2;
            return i2;
        }
        return i;
    }

    public int getConfWidth() {
        return this.confWidth;
    }

    public ECPoint[] getPreComp() {
        return this.preComp;
    }

    public ECPoint[] getPreCompNeg() {
        return this.preCompNeg;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getPromotionCountdown() {
        return this.promotionCountdown;
    }

    public ECPoint getTwice() {
        return this.twice;
    }

    public int getWidth() {
        return this.width;
    }

    public boolean isPromoted() {
        return this.promotionCountdown <= 0;
    }

    public void setConfWidth(int i) {
        this.confWidth = i;
    }

    public void setPreComp(ECPoint[] eCPointArr) {
        this.preComp = eCPointArr;
    }

    public void setPreCompNeg(ECPoint[] eCPointArr) {
        this.preCompNeg = eCPointArr;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void setPromotionCountdown(int i) {
        this.promotionCountdown = i;
    }

    public void setTwice(ECPoint eCPoint) {
        this.twice = eCPoint;
    }

    public void setWidth(int i) {
        this.width = i;
    }
}