package kotlin;

import org.bouncycastle.asn1.cmc.BodyPartID;

/* compiled from: D8$$SyntheticClass */
/* loaded from: classes.dex */
public final /* synthetic */ class UByte$$ExternalSyntheticBackport0 {
    /* renamed from: m */
    public static /* synthetic */ int m165m(int i, int i2) {
        return (int) ((i & BodyPartID.bodyIdMax) / (i2 & BodyPartID.bodyIdMax));
    }

    /* renamed from: m */
    public static /* synthetic */ long m163m(long j, long j2) {
        if (j2 < 0) {
            return (j ^ Long.MIN_VALUE) < (j2 ^ Long.MIN_VALUE) ? j : j - j2;
        } else if (j >= 0) {
            return j % j2;
        } else {
            long j3 = j - ((((j >>> 1) / j2) << 1) * j2);
            if ((j3 ^ Long.MIN_VALUE) < (j2 ^ Long.MIN_VALUE)) {
                j2 = 0;
            }
            return j3 - j2;
        }
    }

    public static /* synthetic */ int m$1(int i, int i2) {
        return (int) ((i & BodyPartID.bodyIdMax) % (i2 & BodyPartID.bodyIdMax));
    }

    public static /* synthetic */ long m$1(long j, long j2) {
        if (j2 < 0) {
            return (j ^ Long.MIN_VALUE) < (j2 ^ Long.MIN_VALUE) ? 0L : 1L;
        } else if (j >= 0) {
            return j / j2;
        } else {
            long j3 = ((j >>> 1) / j2) << 1;
            return j3 + (((j - (j3 * j2)) ^ Long.MIN_VALUE) < (j2 ^ Long.MIN_VALUE) ? 0 : 1);
        }
    }
}