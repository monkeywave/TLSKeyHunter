package org.bouncycastle.asn1.p003x9;

/* renamed from: org.bouncycastle.asn1.x9.X9ECParametersHolder */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/x9/X9ECParametersHolder.class */
public abstract class X9ECParametersHolder {
    private X9ECParameters params;

    public synchronized X9ECParameters getParameters() {
        if (this.params == null) {
            this.params = createParameters();
        }
        return this.params;
    }

    protected abstract X9ECParameters createParameters();
}