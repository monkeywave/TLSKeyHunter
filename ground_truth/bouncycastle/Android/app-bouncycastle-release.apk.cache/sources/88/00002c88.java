package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.ntru.NTRUParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class NTRUParameterSpec implements AlgorithmParameterSpec {
    public static final NTRUParameterSpec ntruhps2048509;
    public static final NTRUParameterSpec ntruhps2048677;
    public static final NTRUParameterSpec ntruhps40961229;
    public static final NTRUParameterSpec ntruhps4096821;
    public static final NTRUParameterSpec ntruhrss1373;
    public static final NTRUParameterSpec ntruhrss701;
    private static Map parameters;
    private final String name;

    static {
        NTRUParameterSpec nTRUParameterSpec = new NTRUParameterSpec(NTRUParameters.ntruhps2048509);
        ntruhps2048509 = nTRUParameterSpec;
        NTRUParameterSpec nTRUParameterSpec2 = new NTRUParameterSpec(NTRUParameters.ntruhps2048677);
        ntruhps2048677 = nTRUParameterSpec2;
        NTRUParameterSpec nTRUParameterSpec3 = new NTRUParameterSpec(NTRUParameters.ntruhps4096821);
        ntruhps4096821 = nTRUParameterSpec3;
        NTRUParameterSpec nTRUParameterSpec4 = new NTRUParameterSpec(NTRUParameters.ntruhps40961229);
        ntruhps40961229 = nTRUParameterSpec4;
        NTRUParameterSpec nTRUParameterSpec5 = new NTRUParameterSpec(NTRUParameters.ntruhrss701);
        ntruhrss701 = nTRUParameterSpec5;
        NTRUParameterSpec nTRUParameterSpec6 = new NTRUParameterSpec(NTRUParameters.ntruhrss1373);
        ntruhrss1373 = nTRUParameterSpec6;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("ntruhps2048509", nTRUParameterSpec);
        parameters.put("ntruhps2048677", nTRUParameterSpec2);
        parameters.put("ntruhps4096821", nTRUParameterSpec3);
        parameters.put("ntruhps40961229", nTRUParameterSpec4);
        parameters.put("ntruhrss701", nTRUParameterSpec5);
        parameters.put("ntruhrss1373", nTRUParameterSpec6);
    }

    private NTRUParameterSpec(NTRUParameters nTRUParameters) {
        this.name = nTRUParameters.getName();
    }

    public static NTRUParameterSpec fromName(String str) {
        return (NTRUParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}