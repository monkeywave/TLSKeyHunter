package org.bouncycastle.i18n.filter;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/i18n/filter/TrustedInput.class */
public class TrustedInput {
    protected Object input;

    public TrustedInput(Object obj) {
        this.input = obj;
    }

    public Object getInput() {
        return this.input;
    }

    public String toString() {
        return this.input.toString();
    }
}