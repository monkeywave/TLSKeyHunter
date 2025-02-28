package org.bouncycastle.asn1;

import java.io.OutputStream;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1Generator.class */
public abstract class ASN1Generator {
    protected OutputStream _out;

    public ASN1Generator(OutputStream outputStream) {
        this._out = outputStream;
    }

    public abstract OutputStream getRawOutputStream();
}