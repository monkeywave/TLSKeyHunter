package org.bouncycastle.pqc.jcajce.spec;

import java.security.spec.AlgorithmParameterSpec;
import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.pqc.crypto.rainbow.RainbowParameters;
import org.bouncycastle.util.Strings;

/* loaded from: classes2.dex */
public class RainbowParameterSpec implements AlgorithmParameterSpec {
    private static Map parameters;
    public static final RainbowParameterSpec rainbowIIIcircumzenithal;
    public static final RainbowParameterSpec rainbowIIIclassic;
    public static final RainbowParameterSpec rainbowIIIcompressed;
    public static final RainbowParameterSpec rainbowVcircumzenithal;
    public static final RainbowParameterSpec rainbowVclassic;
    public static final RainbowParameterSpec rainbowVcompressed;
    private final String name;

    static {
        RainbowParameterSpec rainbowParameterSpec = new RainbowParameterSpec(RainbowParameters.rainbowIIIclassic);
        rainbowIIIclassic = rainbowParameterSpec;
        RainbowParameterSpec rainbowParameterSpec2 = new RainbowParameterSpec(RainbowParameters.rainbowIIIcircumzenithal);
        rainbowIIIcircumzenithal = rainbowParameterSpec2;
        RainbowParameterSpec rainbowParameterSpec3 = new RainbowParameterSpec(RainbowParameters.rainbowIIIcompressed);
        rainbowIIIcompressed = rainbowParameterSpec3;
        RainbowParameterSpec rainbowParameterSpec4 = new RainbowParameterSpec(RainbowParameters.rainbowVclassic);
        rainbowVclassic = rainbowParameterSpec4;
        RainbowParameterSpec rainbowParameterSpec5 = new RainbowParameterSpec(RainbowParameters.rainbowVcircumzenithal);
        rainbowVcircumzenithal = rainbowParameterSpec5;
        RainbowParameterSpec rainbowParameterSpec6 = new RainbowParameterSpec(RainbowParameters.rainbowVcompressed);
        rainbowVcompressed = rainbowParameterSpec6;
        HashMap hashMap = new HashMap();
        parameters = hashMap;
        hashMap.put("rainbow-iii-classic", rainbowParameterSpec);
        parameters.put("rainbow-iii-circumzenithal", rainbowParameterSpec2);
        parameters.put("rainbow-iii-compressed", rainbowParameterSpec3);
        parameters.put("rainbow-v-classic", rainbowParameterSpec4);
        parameters.put("rainbow-v-circumzenithal", rainbowParameterSpec5);
        parameters.put("rainbow-v-compressed", rainbowParameterSpec6);
    }

    private RainbowParameterSpec(RainbowParameters rainbowParameters) {
        this.name = Strings.toUpperCase(rainbowParameters.getName());
    }

    public static RainbowParameterSpec fromName(String str) {
        return (RainbowParameterSpec) parameters.get(Strings.toLowerCase(str));
    }

    public String getName() {
        return this.name;
    }
}