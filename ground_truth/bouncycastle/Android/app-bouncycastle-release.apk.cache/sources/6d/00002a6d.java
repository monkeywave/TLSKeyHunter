package org.bouncycastle.pqc.crypto.rainbow;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;

/* loaded from: classes2.dex */
public class RainbowParameters implements CipherParameters {
    private static final int len_pkseed = 32;
    private static final int len_salt = 16;
    private static final int len_skseed = 32;
    private final Digest hash_algo;

    /* renamed from: m */
    private final int f1380m;

    /* renamed from: n */
    private final int f1381n;
    private final String name;

    /* renamed from: o1 */
    private final int f1382o1;

    /* renamed from: o2 */
    private final int f1383o2;

    /* renamed from: v1 */
    private final int f1384v1;

    /* renamed from: v2 */
    private final int f1385v2;
    private final Version version;
    public static final RainbowParameters rainbowIIIclassic = new RainbowParameters("rainbow-III-classic", 3, Version.CLASSIC);
    public static final RainbowParameters rainbowIIIcircumzenithal = new RainbowParameters("rainbow-III-circumzenithal", 3, Version.CIRCUMZENITHAL);
    public static final RainbowParameters rainbowIIIcompressed = new RainbowParameters("rainbow-III-compressed", 3, Version.COMPRESSED);
    public static final RainbowParameters rainbowVclassic = new RainbowParameters("rainbow-V-classic", 5, Version.CLASSIC);
    public static final RainbowParameters rainbowVcircumzenithal = new RainbowParameters("rainbow-V-circumzenithal", 5, Version.CIRCUMZENITHAL);
    public static final RainbowParameters rainbowVcompressed = new RainbowParameters("rainbow-V-compressed", 5, Version.COMPRESSED);

    private RainbowParameters(String str, int i, Version version) {
        Digest sHA384Digest;
        this.name = str;
        if (i == 3) {
            this.f1384v1 = 68;
            this.f1382o1 = 32;
            this.f1383o2 = 48;
            sHA384Digest = new SHA384Digest();
        } else if (i != 5) {
            throw new IllegalArgumentException("No valid version. Please choose one of the following: 3, 5");
        } else {
            this.f1384v1 = 96;
            this.f1382o1 = 36;
            this.f1383o2 = 64;
            sHA384Digest = new SHA512Digest();
        }
        this.hash_algo = sHA384Digest;
        int i2 = this.f1384v1;
        int i3 = this.f1382o1;
        this.f1385v2 = i2 + i3;
        int i4 = this.f1383o2;
        this.f1381n = i2 + i3 + i4;
        this.f1380m = i3 + i4;
        this.version = version;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Digest getHash_algo() {
        return this.hash_algo;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getLen_pkseed() {
        return 32;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getLen_salt() {
        return 16;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getLen_skseed() {
        return 32;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getM() {
        return this.f1380m;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getN() {
        return this.f1381n;
    }

    public String getName() {
        return this.name;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getO1() {
        return this.f1382o1;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getO2() {
        return this.f1383o2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public int getV1() {
        return this.f1384v1;
    }

    int getV2() {
        return this.f1385v2;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public Version getVersion() {
        return this.version;
    }
}