package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1Type.class */
abstract class ASN1Type {
    final Class javaClass;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Type(Class cls) {
        this.javaClass = cls;
    }

    final Class getJavaClass() {
        return this.javaClass;
    }

    public final boolean equals(Object obj) {
        return this == obj;
    }

    public final int hashCode() {
        return super.hashCode();
    }
}