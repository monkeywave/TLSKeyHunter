package org.bouncycastle.util.p012io.pem;

/* renamed from: org.bouncycastle.util.io.pem.PemHeader */
/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/io/pem/PemHeader.class */
public class PemHeader {
    private String name;
    private String value;

    public PemHeader(String str, String str2) {
        this.name = str;
        this.value = str2;
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    public int hashCode() {
        return getHashCode(this.name) + (31 * getHashCode(this.value));
    }

    public boolean equals(Object obj) {
        if (obj instanceof PemHeader) {
            PemHeader pemHeader = (PemHeader) obj;
            return pemHeader == this || (isEqual(this.name, pemHeader.name) && isEqual(this.value, pemHeader.value));
        }
        return false;
    }

    private int getHashCode(String str) {
        if (str == null) {
            return 1;
        }
        return str.hashCode();
    }

    private boolean isEqual(String str, String str2) {
        if (str == str2) {
            return true;
        }
        if (str == null || str2 == null) {
            return false;
        }
        return str.equals(str2);
    }
}