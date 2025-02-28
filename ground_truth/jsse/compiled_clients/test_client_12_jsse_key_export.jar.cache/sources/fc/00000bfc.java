package org.bouncycastle.jce.provider;

import org.bouncycastle.asn1.x509.ReasonFlags;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jce/provider/ReasonsMask.class */
class ReasonsMask {
    private int _reasons;
    static final ReasonsMask allReasons = new ReasonsMask(33023);

    /* JADX INFO: Access modifiers changed from: package-private */
    public ReasonsMask(ReasonFlags reasonFlags) {
        this._reasons = reasonFlags.intValue();
    }

    private ReasonsMask(int i) {
        this._reasons = i;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ReasonsMask() {
        this(0);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void addReasons(ReasonsMask reasonsMask) {
        this._reasons |= reasonsMask.getReasons();
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean isAllReasons() {
        return this._reasons == allReasons._reasons;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public ReasonsMask intersect(ReasonsMask reasonsMask) {
        ReasonsMask reasonsMask2 = new ReasonsMask();
        reasonsMask2.addReasons(new ReasonsMask(this._reasons & reasonsMask.getReasons()));
        return reasonsMask2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasNewReasons(ReasonsMask reasonsMask) {
        return (this._reasons | (reasonsMask.getReasons() ^ this._reasons)) != 0;
    }

    int getReasons() {
        return this._reasons;
    }
}