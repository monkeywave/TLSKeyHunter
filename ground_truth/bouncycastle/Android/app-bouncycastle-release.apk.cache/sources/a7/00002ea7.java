package org.bouncycastle.util.p019io.pem;

/* renamed from: org.bouncycastle.util.io.pem.PemHeader */
/* loaded from: classes2.dex */
public class PemHeader {
    private String name;
    private String value;

    public PemHeader(String str, String str2) {
        this.name = str;
        this.value = str2;
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

    public boolean equals(Object obj) {
        if (obj instanceof PemHeader) {
            PemHeader pemHeader = (PemHeader) obj;
            return pemHeader == this || (isEqual(this.name, pemHeader.name) && isEqual(this.value, pemHeader.value));
        }
        return false;
    }

    public String getName() {
        return this.name;
    }

    public String getValue() {
        return this.value;
    }

    public int hashCode() {
        return getHashCode(this.name) + (getHashCode(this.value) * 31);
    }
}