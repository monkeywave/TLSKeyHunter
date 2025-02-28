package org.bouncycastle.asn1;

/* loaded from: classes.dex */
abstract class ASN1Type {
    final Class javaClass;

    /* JADX INFO: Access modifiers changed from: package-private */
    public ASN1Type(Class cls) {
        this.javaClass = cls;
    }

    public final boolean equals(Object obj) {
        return this == obj;
    }

    final Class getJavaClass() {
        return this.javaClass;
    }

    public final int hashCode() {
        return super.hashCode();
    }
}