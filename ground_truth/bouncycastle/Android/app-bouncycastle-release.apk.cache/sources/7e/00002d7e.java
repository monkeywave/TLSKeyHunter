package org.bouncycastle.tls;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;

/* loaded from: classes2.dex */
public final class SessionID implements Comparable {

    /* renamed from: id */
    private final byte[] f1550id;

    public SessionID(byte[] bArr) {
        this.f1550id = Arrays.clone(bArr);
    }

    @Override // java.lang.Comparable
    public int compareTo(Object obj) {
        return Arrays.compareUnsigned(this.f1550id, ((SessionID) obj).f1550id);
    }

    public boolean equals(Object obj) {
        if (obj instanceof SessionID) {
            return Arrays.areEqual(this.f1550id, ((SessionID) obj).f1550id);
        }
        return false;
    }

    public byte[] getBytes() {
        return Arrays.clone(this.f1550id);
    }

    public int hashCode() {
        return Arrays.hashCode(this.f1550id);
    }

    public String toString() {
        return Hex.toHexString(this.f1550id);
    }
}