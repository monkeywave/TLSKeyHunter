package org.bouncycastle.crypto.params;

/* loaded from: classes2.dex */
public class GOST3410ValidationParameters {

    /* renamed from: c */
    private int f862c;

    /* renamed from: cL */
    private long f863cL;

    /* renamed from: x0 */
    private int f864x0;
    private long x0L;

    public GOST3410ValidationParameters(int i, int i2) {
        this.f864x0 = i;
        this.f862c = i2;
    }

    public GOST3410ValidationParameters(long j, long j2) {
        this.x0L = j;
        this.f863cL = j2;
    }

    public boolean equals(Object obj) {
        if (obj instanceof GOST3410ValidationParameters) {
            GOST3410ValidationParameters gOST3410ValidationParameters = (GOST3410ValidationParameters) obj;
            return gOST3410ValidationParameters.f862c == this.f862c && gOST3410ValidationParameters.f864x0 == this.f864x0 && gOST3410ValidationParameters.f863cL == this.f863cL && gOST3410ValidationParameters.x0L == this.x0L;
        }
        return false;
    }

    public int getC() {
        return this.f862c;
    }

    public long getCL() {
        return this.f863cL;
    }

    public int getX0() {
        return this.f864x0;
    }

    public long getX0L() {
        return this.x0L;
    }

    public int hashCode() {
        int i = this.f864x0 ^ this.f862c;
        long j = this.x0L;
        int i2 = (i ^ ((int) j)) ^ ((int) (j >> 32));
        long j2 = this.f863cL;
        return (i2 ^ ((int) j2)) ^ ((int) (j2 >> 32));
    }
}