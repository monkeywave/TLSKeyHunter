package org.bouncycastle.crypto.params;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/params/GOST3410ValidationParameters.class */
public class GOST3410ValidationParameters {

    /* renamed from: x0 */
    private int f544x0;

    /* renamed from: c */
    private int f545c;
    private long x0L;

    /* renamed from: cL */
    private long f546cL;

    public GOST3410ValidationParameters(int i, int i2) {
        this.f544x0 = i;
        this.f545c = i2;
    }

    public GOST3410ValidationParameters(long j, long j2) {
        this.x0L = j;
        this.f546cL = j2;
    }

    public int getC() {
        return this.f545c;
    }

    public int getX0() {
        return this.f544x0;
    }

    public long getCL() {
        return this.f546cL;
    }

    public long getX0L() {
        return this.x0L;
    }

    public boolean equals(Object obj) {
        if (obj instanceof GOST3410ValidationParameters) {
            GOST3410ValidationParameters gOST3410ValidationParameters = (GOST3410ValidationParameters) obj;
            return gOST3410ValidationParameters.f545c == this.f545c && gOST3410ValidationParameters.f544x0 == this.f544x0 && gOST3410ValidationParameters.f546cL == this.f546cL && gOST3410ValidationParameters.x0L == this.x0L;
        }
        return false;
    }

    public int hashCode() {
        return ((((this.f544x0 ^ this.f545c) ^ ((int) this.x0L)) ^ ((int) (this.x0L >> 32))) ^ ((int) this.f546cL)) ^ ((int) (this.f546cL >> 32));
    }
}