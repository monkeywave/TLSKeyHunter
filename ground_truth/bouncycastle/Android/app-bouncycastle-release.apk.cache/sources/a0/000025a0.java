package org.bouncycastle.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class SLHDSAParameterSpec implements AlgorithmParameterSpec {
    private static Map parameters;
    public static final SLHDSAParameterSpec slh_dsa_sha2_128f;
    public static final SLHDSAParameterSpec slh_dsa_sha2_128f_with_sha256;
    public static final SLHDSAParameterSpec slh_dsa_sha2_128s;
    public static final SLHDSAParameterSpec slh_dsa_sha2_128s_with_sha256;
    public static final SLHDSAParameterSpec slh_dsa_sha2_192f;
    public static final SLHDSAParameterSpec slh_dsa_sha2_192f_with_sha512;
    public static final SLHDSAParameterSpec slh_dsa_sha2_192s;
    public static final SLHDSAParameterSpec slh_dsa_sha2_192s_with_sha512;
    public static final SLHDSAParameterSpec slh_dsa_sha2_256f;
    public static final SLHDSAParameterSpec slh_dsa_sha2_256f_with_sha512;
    public static final SLHDSAParameterSpec slh_dsa_sha2_256s;
    public static final SLHDSAParameterSpec slh_dsa_sha2_256s_with_sha512;
    public static final SLHDSAParameterSpec slh_dsa_shake_128f;
    public static final SLHDSAParameterSpec slh_dsa_shake_128f_with_shake128;
    public static final SLHDSAParameterSpec slh_dsa_shake_128s;
    public static final SLHDSAParameterSpec slh_dsa_shake_128s_with_shake128;
    public static final SLHDSAParameterSpec slh_dsa_shake_192f;
    public static final SLHDSAParameterSpec slh_dsa_shake_192f_with_shake256;
    public static final SLHDSAParameterSpec slh_dsa_shake_192s;
    public static final SLHDSAParameterSpec slh_dsa_shake_192s_with_shake256;
    public static final SLHDSAParameterSpec slh_dsa_shake_256f;
    public static final SLHDSAParameterSpec slh_dsa_shake_256f_with_shake256;
    public static final SLHDSAParameterSpec slh_dsa_shake_256s;
    public static final SLHDSAParameterSpec slh_dsa_shake_256s_with_shake256;
    private final String name;

    static {
        SLHDSAParameterSpec sLHDSAParameterSpec = new SLHDSAParameterSpec("SLH-DSA-SHA2-128F");
        slh_dsa_sha2_128f = sLHDSAParameterSpec;
        SLHDSAParameterSpec sLHDSAParameterSpec2 = new SLHDSAParameterSpec("SLH-DSA-SHA2-128S");
        slh_dsa_sha2_128s = sLHDSAParameterSpec2;
        SLHDSAParameterSpec sLHDSAParameterSpec3 = new SLHDSAParameterSpec("SLH-DSA-SHA2-192F");
        slh_dsa_sha2_192f = sLHDSAParameterSpec3;
        SLHDSAParameterSpec sLHDSAParameterSpec4 = new SLHDSAParameterSpec("SLH-DSA-SHA2-192S");
        slh_dsa_sha2_192s = sLHDSAParameterSpec4;
        SLHDSAParameterSpec sLHDSAParameterSpec5 = new SLHDSAParameterSpec("SLH-DSA-SHA2-256F");
        slh_dsa_sha2_256f = sLHDSAParameterSpec5;
        SLHDSAParameterSpec sLHDSAParameterSpec6 = new SLHDSAParameterSpec("SLH-DSA-SHA2-256S");
        slh_dsa_sha2_256s = sLHDSAParameterSpec6;
        SLHDSAParameterSpec sLHDSAParameterSpec7 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-128F");
        slh_dsa_shake_128f = sLHDSAParameterSpec7;
        SLHDSAParameterSpec sLHDSAParameterSpec8 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-128S");
        slh_dsa_shake_128s = sLHDSAParameterSpec8;
        SLHDSAParameterSpec sLHDSAParameterSpec9 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-192F");
        slh_dsa_shake_192f = sLHDSAParameterSpec9;
        SLHDSAParameterSpec sLHDSAParameterSpec10 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-192S");
        slh_dsa_shake_192s = sLHDSAParameterSpec10;
        SLHDSAParameterSpec sLHDSAParameterSpec11 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-256F");
        slh_dsa_shake_256f = sLHDSAParameterSpec11;
        SLHDSAParameterSpec sLHDSAParameterSpec12 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-256S");
        slh_dsa_shake_256s = sLHDSAParameterSpec12;
        SLHDSAParameterSpec sLHDSAParameterSpec13 = new SLHDSAParameterSpec("SLH-DSA-SHA2-128F-WITH-SHA256");
        slh_dsa_sha2_128f_with_sha256 = sLHDSAParameterSpec13;
        SLHDSAParameterSpec sLHDSAParameterSpec14 = new SLHDSAParameterSpec("SLH-DSA-SHA2-128S-WITH-SHA256");
        slh_dsa_sha2_128s_with_sha256 = sLHDSAParameterSpec14;
        SLHDSAParameterSpec sLHDSAParameterSpec15 = new SLHDSAParameterSpec("SLH-DSA-SHA2-192F-WITH-SHA512");
        slh_dsa_sha2_192f_with_sha512 = sLHDSAParameterSpec15;
        SLHDSAParameterSpec sLHDSAParameterSpec16 = new SLHDSAParameterSpec("SLH-DSA-SHA2-192S-WITH-SHA512");
        slh_dsa_sha2_192s_with_sha512 = sLHDSAParameterSpec16;
        SLHDSAParameterSpec sLHDSAParameterSpec17 = new SLHDSAParameterSpec("SLH-DSA-SHA2-256F-WITH-SHA512");
        slh_dsa_sha2_256f_with_sha512 = sLHDSAParameterSpec17;
        SLHDSAParameterSpec sLHDSAParameterSpec18 = new SLHDSAParameterSpec("SLH-DSA-SHA2-256S-WITH-SHA512");
        slh_dsa_sha2_256s_with_sha512 = sLHDSAParameterSpec18;
        SLHDSAParameterSpec sLHDSAParameterSpec19 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-128F-WITH-SHAKE128");
        slh_dsa_shake_128f_with_shake128 = sLHDSAParameterSpec19;
        SLHDSAParameterSpec sLHDSAParameterSpec20 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-128S-WITH-SHAKE128");
        slh_dsa_shake_128s_with_shake128 = sLHDSAParameterSpec20;
        SLHDSAParameterSpec sLHDSAParameterSpec21 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-192F-WITH-SHAKE256");
        slh_dsa_shake_192f_with_shake256 = sLHDSAParameterSpec21;
        SLHDSAParameterSpec sLHDSAParameterSpec22 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-192S-WITH-SHAKE256");
        slh_dsa_shake_192s_with_shake256 = sLHDSAParameterSpec22;
        SLHDSAParameterSpec sLHDSAParameterSpec23 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-256F-WITH-SHAKE256");
        slh_dsa_shake_256f_with_shake256 = sLHDSAParameterSpec23;
        SLHDSAParameterSpec sLHDSAParameterSpec24 = new SLHDSAParameterSpec("SLH-DSA-SHAKE-256S-WITH-SHAKE256");
        slh_dsa_shake_256s_with_shake256 = sLHDSAParameterSpec24;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("slh-dsa-sha2-128f", sLHDSAParameterSpec);
        parameters.put("slh-dsa-sha2-128s", sLHDSAParameterSpec2);
        parameters.put("slh-dsa-sha2-192f", sLHDSAParameterSpec3);
        parameters.put("slh-dsa-sha2-192s", sLHDSAParameterSpec4);
        parameters.put("slh-dsa-sha2-256f", sLHDSAParameterSpec5);
        parameters.put("slh-dsa-sha2-256s", sLHDSAParameterSpec6);
        parameters.put("sha2-128f", sLHDSAParameterSpec);
        parameters.put("sha2-128s", sLHDSAParameterSpec2);
        parameters.put("sha2-192f", sLHDSAParameterSpec3);
        parameters.put("sha2-192s", sLHDSAParameterSpec4);
        parameters.put("sha2-256f", sLHDSAParameterSpec5);
        parameters.put("sha2-256s", sLHDSAParameterSpec6);
        parameters.put("slh-dsa-shake-128f", sLHDSAParameterSpec7);
        parameters.put("slh-dsa-shake-128s", sLHDSAParameterSpec8);
        parameters.put("slh-dsa-shake-192f", sLHDSAParameterSpec9);
        parameters.put("slh-dsa-shake-192s", sLHDSAParameterSpec10);
        parameters.put("slh-dsa-shake-256f", sLHDSAParameterSpec11);
        parameters.put("slh-dsa-shake-256s", sLHDSAParameterSpec12);
        parameters.put("shake-128f", sLHDSAParameterSpec7);
        parameters.put("shake-128s", sLHDSAParameterSpec8);
        parameters.put("shake-192f", sLHDSAParameterSpec9);
        parameters.put("shake-192s", sLHDSAParameterSpec10);
        parameters.put("shake-256f", sLHDSAParameterSpec11);
        parameters.put("shake-256s", sLHDSAParameterSpec12);
        parameters.put("slh-dsa-sha2-128f-with-sha256", sLHDSAParameterSpec13);
        parameters.put("slh-dsa-sha2-128s-with-sha256", sLHDSAParameterSpec14);
        parameters.put("slh-dsa-sha2-192f-with-sha512", sLHDSAParameterSpec15);
        parameters.put("slh-dsa-sha2-192s-with-sha512", sLHDSAParameterSpec16);
        parameters.put("slh-dsa-sha2-256f-with-sha512", sLHDSAParameterSpec17);
        parameters.put("slh-dsa-sha2-256s-with-sha512", sLHDSAParameterSpec18);
        parameters.put("sha2-128f-with-sha256", sLHDSAParameterSpec13);
        parameters.put("sha2-128s-with-sha256", sLHDSAParameterSpec14);
        parameters.put("sha2-192f-with-sha512", sLHDSAParameterSpec15);
        parameters.put("sha2-192s-with-sha512", sLHDSAParameterSpec16);
        parameters.put("sha2-256f-with-sha512", sLHDSAParameterSpec17);
        parameters.put("sha2-256s-with-sha512", sLHDSAParameterSpec18);
        parameters.put("slh-dsa-shake-128f-with-shake128", sLHDSAParameterSpec19);
        parameters.put("slh-dsa-shake-128s-with-shake128", sLHDSAParameterSpec20);
        parameters.put("slh-dsa-shake-192f-with-shake256", sLHDSAParameterSpec21);
        parameters.put("slh-dsa-shake-192s-with-shake256", sLHDSAParameterSpec22);
        parameters.put("slh-dsa-shake-256f-with-shake256", sLHDSAParameterSpec23);
        parameters.put("slh-dsa-shake-256s-with-shake256", sLHDSAParameterSpec24);
        parameters.put("shake-128f-with-shake128", sLHDSAParameterSpec19);
        parameters.put("shake-128s-with-shake128", sLHDSAParameterSpec20);
        parameters.put("shake-192f-with-shake256", sLHDSAParameterSpec21);
        parameters.put("shake-192s-with-shake256", sLHDSAParameterSpec22);
        parameters.put("shake-256f-with-shake256", sLHDSAParameterSpec23);
        parameters.put("shake-256s-with-shake256", sLHDSAParameterSpec24);
    }

    private SLHDSAParameterSpec(String str) {
        this.name = str;
    }

    public static SLHDSAParameterSpec fromName(String str) {
        if (str != null) {
            SLHDSAParameterSpec sLHDSAParameterSpec = (SLHDSAParameterSpec) parameters.get(Strings.toLowerCase(str));
            if (sLHDSAParameterSpec != null) {
                return sLHDSAParameterSpec;
            }
            throw new IllegalArgumentException("unknown parameter name: " + str);
        }
        throw new NullPointerException("name cannot be null");
    }

    public String getName() {
        return this.name;
    }
}