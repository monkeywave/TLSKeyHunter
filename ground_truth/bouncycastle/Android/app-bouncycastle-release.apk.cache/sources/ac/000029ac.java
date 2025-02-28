package org.bouncycastle.pqc.crypto.gemss;

import org.bouncycastle.asn1.cmc.BodyPartID;

/* loaded from: classes2.dex */
public class GeMSSUtils {
    /* JADX INFO: Access modifiers changed from: package-private */
    public static long CMP_LT_UINT(long j, long j2) {
        long j3 = j >>> 63;
        long j4 = j2 >>> 63;
        long j5 = j3 ^ j4;
        return ((((j & Long.MAX_VALUE) - (j2 & Long.MAX_VALUE)) >>> 63) & (1 ^ j5)) ^ (((j3 - j4) >>> 63) & j5);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static int Highest_One(int i) {
        int i2 = i | (i >>> 1);
        int i3 = i2 | (i2 >>> 2);
        int i4 = i3 | (i3 >>> 4);
        int i5 = i4 | (i4 >>> 8);
        int i6 = i5 | (i5 >>> 16);
        return i6 ^ (i6 >>> 1);
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static long NORBITS_UINT(long j) {
        return (((j | (j << 32)) >>> 32) - 1) >>> 63;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static long ORBITS_UINT(long j) {
        return (((j | (j << 32)) >>> 32) + BodyPartID.bodyIdMax) >>> 32;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static long XORBITS_UINT(long j) {
        long j2 = j ^ (j << 1);
        return (((j2 ^ (j2 << 2)) & (-8608480567731124088L)) * 1229782938247303441L) >>> 63;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static long maskUINT(int i) {
        if (i != 0) {
            return (1 << i) - 1;
        }
        return -1L;
    }
}