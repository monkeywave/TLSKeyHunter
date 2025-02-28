package org.bouncycastle.math.p010ec;

/* renamed from: org.bouncycastle.math.ec.ValidityPrecompInfo */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/math/ec/ValidityPrecompInfo.class */
class ValidityPrecompInfo implements PreCompInfo {
    static final String PRECOMP_NAME = "bc_validity";
    private boolean failed = false;
    private boolean curveEquationPassed = false;
    private boolean orderPassed = false;

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasFailed() {
        return this.failed;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void reportFailed() {
        this.failed = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasCurveEquationPassed() {
        return this.curveEquationPassed;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void reportCurveEquationPassed() {
        this.curveEquationPassed = true;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public boolean hasOrderPassed() {
        return this.orderPassed;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public void reportOrderPassed() {
        this.orderPassed = true;
    }
}