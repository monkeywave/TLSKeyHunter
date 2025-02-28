package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.cmce.CMCEParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class CMCEParameterSpec implements AlgorithmParameterSpec {
    public static final CMCEParameterSpec mceliece348864;
    public static final CMCEParameterSpec mceliece348864f;
    public static final CMCEParameterSpec mceliece460896;
    public static final CMCEParameterSpec mceliece460896f;
    public static final CMCEParameterSpec mceliece6688128;
    public static final CMCEParameterSpec mceliece6688128f;
    public static final CMCEParameterSpec mceliece6960119;
    public static final CMCEParameterSpec mceliece6960119f;
    public static final CMCEParameterSpec mceliece8192128;
    public static final CMCEParameterSpec mceliece8192128f;
    private static Map parameters;
    private final String name;

    static {
        CMCEParameterSpec cMCEParameterSpec = new CMCEParameterSpec(CMCEParameters.mceliece348864r3);
        mceliece348864 = cMCEParameterSpec;
        CMCEParameterSpec cMCEParameterSpec2 = new CMCEParameterSpec(CMCEParameters.mceliece348864fr3);
        mceliece348864f = cMCEParameterSpec2;
        CMCEParameterSpec cMCEParameterSpec3 = new CMCEParameterSpec(CMCEParameters.mceliece460896r3);
        mceliece460896 = cMCEParameterSpec3;
        CMCEParameterSpec cMCEParameterSpec4 = new CMCEParameterSpec(CMCEParameters.mceliece460896fr3);
        mceliece460896f = cMCEParameterSpec4;
        CMCEParameterSpec cMCEParameterSpec5 = new CMCEParameterSpec(CMCEParameters.mceliece6688128r3);
        mceliece6688128 = cMCEParameterSpec5;
        CMCEParameterSpec cMCEParameterSpec6 = new CMCEParameterSpec(CMCEParameters.mceliece6688128fr3);
        mceliece6688128f = cMCEParameterSpec6;
        CMCEParameterSpec cMCEParameterSpec7 = new CMCEParameterSpec(CMCEParameters.mceliece6960119r3);
        mceliece6960119 = cMCEParameterSpec7;
        CMCEParameterSpec cMCEParameterSpec8 = new CMCEParameterSpec(CMCEParameters.mceliece6960119fr3);
        mceliece6960119f = cMCEParameterSpec8;
        CMCEParameterSpec cMCEParameterSpec9 = new CMCEParameterSpec(CMCEParameters.mceliece8192128r3);
        mceliece8192128 = cMCEParameterSpec9;
        CMCEParameterSpec cMCEParameterSpec10 = new CMCEParameterSpec(CMCEParameters.mceliece8192128fr3);
        mceliece8192128f = cMCEParameterSpec10;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("mceliece348864", cMCEParameterSpec);
        parameters.put("mceliece348864f", cMCEParameterSpec2);
        parameters.put("mceliece460896", cMCEParameterSpec3);
        parameters.put("mceliece460896f", cMCEParameterSpec4);
        parameters.put("mceliece6688128", cMCEParameterSpec5);
        parameters.put("mceliece6688128f", cMCEParameterSpec6);
        parameters.put("mceliece6960119", cMCEParameterSpec7);
        parameters.put("mceliece6960119f", cMCEParameterSpec8);
        parameters.put("mceliece8192128", cMCEParameterSpec9);
        parameters.put("mceliece8192128f", cMCEParameterSpec10);
    }

    private CMCEParameterSpec(CMCEParameters cMCEParameters) {
        this.name = cMCEParameters.getName();
    }

    public static CMCEParameterSpec fromName(String str) {
        return (CMCEParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}