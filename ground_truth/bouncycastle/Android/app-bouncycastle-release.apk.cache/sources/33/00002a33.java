package org.bouncycastle.pqc.crypto.ntru;

import org.bouncycastle.pqc.crypto.KEMParameters;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS2048509;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS2048677;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS40961229;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHPS4096821;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSS1373;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUHRSS701;
import org.bouncycastle.pqc.math.ntru.parameters.NTRUParameterSet;

/* loaded from: classes2.dex */
public class NTRUParameters implements KEMParameters {
    private final String name;
    final NTRUParameterSet parameterSet;
    public static final NTRUParameters ntruhps2048509 = new NTRUParameters("ntruhps2048509", new NTRUHPS2048509());
    public static final NTRUParameters ntruhps2048677 = new NTRUParameters("ntruhps2048677", new NTRUHPS2048677());
    public static final NTRUParameters ntruhps4096821 = new NTRUParameters("ntruhps4096821", new NTRUHPS4096821());
    public static final NTRUParameters ntruhps40961229 = new NTRUParameters("ntruhps40961229", new NTRUHPS40961229());
    public static final NTRUParameters ntruhrss701 = new NTRUParameters("ntruhrss701", new NTRUHRSS701());
    public static final NTRUParameters ntruhrss1373 = new NTRUParameters("ntruhrss1373", new NTRUHRSS1373());

    private NTRUParameters(String str, NTRUParameterSet nTRUParameterSet) {
        this.name = str;
        this.parameterSet = nTRUParameterSet;
    }

    public String getName() {
        return this.name;
    }

    public int getSessionKeySize() {
        return this.parameterSet.sharedKeyBytes() * 8;
    }
}