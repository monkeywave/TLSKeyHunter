package org.bouncycastle.pqc.crypto.gemss;

import androidx.constraintlayout.core.motion.utils.TypedValues;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.tls.CipherSuite;
import org.bouncycastle.tls.NamedGroup;
import org.bouncycastle.tls.SignatureScheme;
import org.bouncycastle.util.Integers;
import org.bouncycastle.util.Pack;

/* loaded from: classes2.dex */
public class GeMSSParameters {
    public static final GeMSSParameters bluegemss128;
    public static final GeMSSParameters bluegemss192;
    public static final GeMSSParameters bluegemss256;
    private static final Integer bluegemss_128;
    private static final Integer bluegemss_192;
    private static final Integer bluegemss_256;
    public static final GeMSSParameters cyangemss128;
    public static final GeMSSParameters cyangemss192;
    public static final GeMSSParameters cyangemss256;
    private static final Integer cyangemss_128;
    private static final Integer cyangemss_192;
    private static final Integer cyangemss_256;
    public static final GeMSSParameters dualmodems128;
    public static final GeMSSParameters dualmodems192;
    public static final GeMSSParameters dualmodems256;
    private static final Integer dualmodems_128;
    private static final Integer dualmodems_192;
    private static final Integer dualmodems_256;
    public static final GeMSSParameters fgemss128;
    public static final GeMSSParameters fgemss192;
    public static final GeMSSParameters fgemss256;
    private static final Integer fgemss_128;
    private static final Integer fgemss_192;
    private static final Integer fgemss_256;
    public static final GeMSSParameters gemss128;
    public static final GeMSSParameters gemss192;
    public static final GeMSSParameters gemss256;
    private static final Integer gemss_128;
    private static final Integer gemss_192;
    private static final Integer gemss_256;
    public static final GeMSSParameters magentagemss128;
    public static final GeMSSParameters magentagemss192;
    public static final GeMSSParameters magentagemss256;
    private static final Integer magentagemss_128;
    private static final Integer magentagemss_192;
    private static final Integer magentagemss_256;
    private static final Map<Integer, GeMSSParameters> oidToParams;
    private static final Map<GeMSSParameters, Integer> paramsToOid;
    public static final GeMSSParameters redgemss128;
    public static final GeMSSParameters redgemss192;
    public static final GeMSSParameters redgemss256;
    private static final Integer redgemss_128;
    private static final Integer redgemss_192;
    private static final Integer redgemss_256;
    public static final GeMSSParameters whitegemss128;
    public static final GeMSSParameters whitegemss192;
    public static final GeMSSParameters whitegemss256;
    private static final Integer whitegemss_128;
    private static final Integer whitegemss_192;
    private static final Integer whitegemss_256;
    private final GeMSSEngine engine;
    private final String name;

    static {
        GeMSSParameters geMSSParameters = new GeMSSParameters("gemss128", 128, CipherSuite.TLS_PSK_WITH_AES_128_CBC_SHA256, 12, 12, 4, 513, 9, 0);
        gemss128 = geMSSParameters;
        GeMSSParameters geMSSParameters2 = new GeMSSParameters("gemss192", 192, 265, 20, 22, 4, 513, 9, 0);
        gemss192 = geMSSParameters2;
        GeMSSParameters geMSSParameters3 = new GeMSSParameters("gemss256", 256, 354, 33, 30, 4, 513, 9, 0);
        gemss256 = geMSSParameters3;
        GeMSSParameters geMSSParameters4 = new GeMSSParameters("bluegemss128", 128, CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384, 14, 13, 4, 129, 7, 0);
        bluegemss128 = geMSSParameters4;
        GeMSSParameters geMSSParameters5 = new GeMSSParameters("bluegemss192", 192, 265, 23, 22, 4, 129, 7, 0);
        bluegemss192 = geMSSParameters5;
        GeMSSParameters geMSSParameters6 = new GeMSSParameters("bluegemss256", 256, 358, 32, 34, 4, 129, 7, 0);
        bluegemss256 = geMSSParameters6;
        GeMSSParameters geMSSParameters7 = new GeMSSParameters("redgemss128", 128, CipherSuite.TLS_PSK_WITH_NULL_SHA384, 15, 15, 4, 17, 4, 0);
        redgemss128 = geMSSParameters7;
        GeMSSParameters geMSSParameters8 = new GeMSSParameters("redgemss192", 192, 266, 25, 23, 4, 17, 4, 0);
        redgemss192 = geMSSParameters8;
        GeMSSParameters geMSSParameters9 = new GeMSSParameters("redgemss256", 256, 358, 35, 34, 4, 17, 4, 0);
        redgemss256 = geMSSParameters9;
        GeMSSParameters geMSSParameters10 = new GeMSSParameters("whitegemss128", 128, CipherSuite.TLS_PSK_WITH_AES_256_CBC_SHA384, 12, 12, 3, 513, 9, 0);
        whitegemss128 = geMSSParameters10;
        GeMSSParameters geMSSParameters11 = new GeMSSParameters("whitegemss192", 192, 268, 21, 21, 3, 513, 9, 0);
        whitegemss192 = geMSSParameters11;
        GeMSSParameters geMSSParameters12 = new GeMSSParameters("whitegemss256", 256, 364, 29, 31, 3, 513, 9, 0);
        whitegemss256 = geMSSParameters12;
        GeMSSParameters geMSSParameters13 = new GeMSSParameters("cyangemss128", 128, CipherSuite.TLS_PSK_WITH_NULL_SHA384, 13, 14, 3, 129, 7, 0);
        cyangemss128 = geMSSParameters13;
        GeMSSParameters geMSSParameters14 = new GeMSSParameters("cyangemss192", 192, 270, 22, 23, 3, 129, 7, 0);
        cyangemss192 = geMSSParameters14;
        GeMSSParameters geMSSParameters15 = new GeMSSParameters("cyangemss256", 256, 364, 32, 31, 3, 129, 7, 0);
        cyangemss256 = geMSSParameters15;
        GeMSSParameters geMSSParameters16 = new GeMSSParameters("magentagemss128", 128, CipherSuite.TLS_DHE_PSK_WITH_AES_128_CBC_SHA256, 15, 15, 3, 17, 4, 0);
        magentagemss128 = geMSSParameters16;
        GeMSSParameters geMSSParameters17 = new GeMSSParameters("magentagemss192", 192, 271, 24, 24, 3, 17, 4, 0);
        magentagemss192 = geMSSParameters17;
        GeMSSParameters geMSSParameters18 = new GeMSSParameters("magentagemss256", 256, 366, 33, 33, 3, 17, 4, 0);
        magentagemss256 = geMSSParameters18;
        GeMSSParameters geMSSParameters19 = new GeMSSParameters("fgemss128", 128, 266, 11, 10, 1, 129, 7, 0);
        fgemss128 = geMSSParameters19;
        GeMSSParameters geMSSParameters20 = new GeMSSParameters("fgemss192", 192, TypedValues.CycleType.TYPE_VISIBILITY, 18, 18, 1, 640, 9, 7);
        fgemss192 = geMSSParameters20;
        GeMSSParameters geMSSParameters21 = new GeMSSParameters("fgemss256", 256, 537, 26, 25, 1, 1152, 10, 7);
        fgemss256 = geMSSParameters21;
        GeMSSParameters geMSSParameters22 = new GeMSSParameters("dualmodems128", 128, 266, 11, 10, 1, 129, 7, 0);
        dualmodems128 = geMSSParameters22;
        GeMSSParameters geMSSParameters23 = new GeMSSParameters("dualmodems192", 192, TypedValues.CycleType.TYPE_VISIBILITY, 18, 18, 1, 129, 7, 0);
        dualmodems192 = geMSSParameters23;
        GeMSSParameters geMSSParameters24 = new GeMSSParameters("dualmodems256", 256, 544, 32, 32, 1, 129, 7, 0);
        dualmodems256 = geMSSParameters24;
        Integer valueOf = Integers.valueOf(257);
        gemss_128 = valueOf;
        Integer valueOf2 = Integers.valueOf(NamedGroup.ffdhe4096);
        gemss_192 = valueOf2;
        Integer valueOf3 = Integers.valueOf(NamedGroup.ffdhe6144);
        gemss_256 = valueOf3;
        Integer valueOf4 = Integers.valueOf(513);
        bluegemss_128 = valueOf4;
        Integer valueOf5 = Integers.valueOf(514);
        bluegemss_192 = valueOf5;
        Integer valueOf6 = Integers.valueOf(SignatureScheme.ecdsa_sha1);
        bluegemss_256 = valueOf6;
        Integer valueOf7 = Integers.valueOf(769);
        redgemss_128 = valueOf7;
        Integer valueOf8 = Integers.valueOf(770);
        redgemss_192 = valueOf8;
        Integer valueOf9 = Integers.valueOf(771);
        redgemss_256 = valueOf9;
        Integer valueOf10 = Integers.valueOf(1025);
        whitegemss_128 = valueOf10;
        Integer valueOf11 = Integers.valueOf(1026);
        whitegemss_192 = valueOf11;
        Integer valueOf12 = Integers.valueOf(SignatureScheme.ecdsa_secp256r1_sha256);
        whitegemss_256 = valueOf12;
        Integer valueOf13 = Integers.valueOf(SignatureScheme.rsa_pkcs1_sha384);
        cyangemss_128 = valueOf13;
        Integer valueOf14 = Integers.valueOf(1282);
        cyangemss_192 = valueOf14;
        Integer valueOf15 = Integers.valueOf(SignatureScheme.ecdsa_secp384r1_sha384);
        cyangemss_256 = valueOf15;
        Integer valueOf16 = Integers.valueOf(SignatureScheme.rsa_pkcs1_sha512);
        magentagemss_128 = valueOf16;
        Integer valueOf17 = Integers.valueOf(1538);
        magentagemss_192 = valueOf17;
        Integer valueOf18 = Integers.valueOf(SignatureScheme.ecdsa_secp521r1_sha512);
        magentagemss_256 = valueOf18;
        Integer valueOf19 = Integers.valueOf(1793);
        fgemss_128 = valueOf19;
        Integer valueOf20 = Integers.valueOf(1794);
        fgemss_192 = valueOf20;
        Integer valueOf21 = Integers.valueOf(1795);
        fgemss_256 = valueOf21;
        Integer valueOf22 = Integers.valueOf(2049);
        dualmodems_128 = valueOf22;
        Integer valueOf23 = Integers.valueOf(2050);
        dualmodems_192 = valueOf23;
        Integer valueOf24 = Integers.valueOf(2051);
        dualmodems_256 = valueOf24;
        HashMap hashMap = new HashMap();
        oidToParams = hashMap;
        HashMap hashMap2 = new HashMap();
        paramsToOid = hashMap2;
        hashMap.put(valueOf, geMSSParameters);
        hashMap.put(valueOf2, geMSSParameters2);
        hashMap.put(valueOf3, geMSSParameters3);
        hashMap.put(valueOf4, geMSSParameters4);
        hashMap.put(valueOf5, geMSSParameters5);
        hashMap.put(valueOf6, geMSSParameters6);
        hashMap.put(valueOf7, geMSSParameters7);
        hashMap.put(valueOf8, geMSSParameters8);
        hashMap.put(valueOf9, geMSSParameters9);
        hashMap.put(valueOf10, geMSSParameters10);
        hashMap.put(valueOf11, geMSSParameters11);
        hashMap.put(valueOf12, geMSSParameters12);
        hashMap.put(valueOf13, geMSSParameters13);
        hashMap.put(valueOf14, geMSSParameters14);
        hashMap.put(valueOf15, geMSSParameters15);
        hashMap.put(valueOf16, geMSSParameters16);
        hashMap.put(valueOf17, geMSSParameters17);
        hashMap.put(valueOf18, geMSSParameters18);
        hashMap.put(valueOf19, geMSSParameters19);
        hashMap.put(valueOf20, geMSSParameters20);
        hashMap.put(valueOf21, geMSSParameters21);
        hashMap.put(valueOf22, geMSSParameters22);
        hashMap.put(valueOf23, geMSSParameters23);
        hashMap.put(valueOf24, geMSSParameters24);
        hashMap2.put(geMSSParameters, valueOf);
        hashMap2.put(geMSSParameters2, valueOf2);
        hashMap2.put(geMSSParameters3, valueOf3);
        hashMap2.put(geMSSParameters4, valueOf4);
        hashMap2.put(geMSSParameters5, valueOf5);
        hashMap2.put(geMSSParameters6, valueOf6);
        hashMap2.put(geMSSParameters7, valueOf7);
        hashMap2.put(geMSSParameters8, valueOf8);
        hashMap2.put(geMSSParameters9, valueOf9);
        hashMap2.put(geMSSParameters10, valueOf10);
        hashMap2.put(geMSSParameters11, valueOf11);
        hashMap2.put(geMSSParameters12, valueOf12);
        hashMap2.put(geMSSParameters13, valueOf13);
        hashMap2.put(geMSSParameters14, valueOf14);
        hashMap2.put(geMSSParameters15, valueOf15);
        hashMap2.put(geMSSParameters16, valueOf16);
        hashMap2.put(geMSSParameters17, valueOf17);
        hashMap2.put(geMSSParameters18, valueOf18);
        hashMap2.put(geMSSParameters19, valueOf19);
        hashMap2.put(geMSSParameters20, valueOf20);
        hashMap2.put(geMSSParameters21, valueOf21);
        hashMap2.put(geMSSParameters22, valueOf22);
        hashMap2.put(geMSSParameters23, valueOf23);
        hashMap2.put(geMSSParameters24, valueOf24);
    }

    private GeMSSParameters(String str, int i, int i2, int i3, int i4, int i5, int i6, int i7, int i8) {
        this.name = str;
        this.engine = new GeMSSEngine(i, i2, i3, i4, i5, i6, i7, i8);
    }

    public static Integer getID(GeMSSParameters geMSSParameters) {
        return paramsToOid.get(geMSSParameters);
    }

    public static GeMSSParameters getParams(Integer num) {
        return oidToParams.get(num);
    }

    public byte[] getEncoded() {
        return Pack.intToBigEndian(getID(this).intValue());
    }

    public GeMSSEngine getEngine() {
        return this.engine;
    }

    public String getName() {
        return this.name;
    }
}