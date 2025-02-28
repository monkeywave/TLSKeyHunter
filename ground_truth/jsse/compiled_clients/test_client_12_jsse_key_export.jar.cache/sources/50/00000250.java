package org.bouncycastle.asn1;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/OIDTokenizer.class */
public class OIDTokenizer {
    private String oid;
    private int index = 0;

    public OIDTokenizer(String str) {
        this.oid = str;
    }

    public boolean hasMoreTokens() {
        return this.index != -1;
    }

    public String nextToken() {
        if (this.index == -1) {
            return null;
        }
        int indexOf = this.oid.indexOf(46, this.index);
        if (indexOf == -1) {
            String substring = this.oid.substring(this.index);
            this.index = -1;
            return substring;
        }
        String substring2 = this.oid.substring(this.index, indexOf);
        this.index = indexOf + 1;
        return substring2;
    }
}