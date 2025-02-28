package org.bouncycastle.tls.crypto.impl.jcajce;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.KeySpec;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.jcajce.spec.DHDomainParameterSpec;
import org.bouncycastle.jcajce.spec.DHExtendedPublicKeySpec;
import org.bouncycastle.tls.crypto.DHGroup;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class DHUtil {
    DHUtil() {
    }

    static AlgorithmParameterSpec createInitSpec(DHGroup dHGroup) {
        return new DHDomainParameterSpec(dHGroup.getP(), dHGroup.getQ(), dHGroup.getG(), dHGroup.getL());
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static KeySpec createPublicKeySpec(BigInteger bigInteger, DHParameterSpec dHParameterSpec) {
        return new DHExtendedPublicKeySpec(bigInteger, dHParameterSpec);
    }

    static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto jcaTlsCrypto, AlgorithmParameterSpec algorithmParameterSpec) {
        try {
            AlgorithmParameters createAlgorithmParameters = jcaTlsCrypto.getHelper().createAlgorithmParameters("DiffieHellman");
            createAlgorithmParameters.init(algorithmParameterSpec);
            if (((DHParameterSpec) createAlgorithmParameters.getParameterSpec(DHParameterSpec.class)) != null) {
                return createAlgorithmParameters;
            }
            return null;
        } catch (AssertionError | Exception unused) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static AlgorithmParameters getAlgorithmParameters(JcaTlsCrypto jcaTlsCrypto, DHGroup dHGroup) {
        return getAlgorithmParameters(jcaTlsCrypto, createInitSpec(dHGroup));
    }

    static DHParameterSpec getDHParameterSpec(JcaTlsCrypto jcaTlsCrypto, AlgorithmParameterSpec algorithmParameterSpec) {
        try {
            AlgorithmParameters createAlgorithmParameters = jcaTlsCrypto.getHelper().createAlgorithmParameters("DiffieHellman");
            createAlgorithmParameters.init(algorithmParameterSpec);
            DHParameterSpec dHParameterSpec = (DHParameterSpec) createAlgorithmParameters.getParameterSpec(DHParameterSpec.class);
            if (dHParameterSpec != null) {
                return dHParameterSpec;
            }
            return null;
        } catch (AssertionError | Exception unused) {
            return null;
        }
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static DHParameterSpec getDHParameterSpec(JcaTlsCrypto jcaTlsCrypto, DHGroup dHGroup) {
        return getDHParameterSpec(jcaTlsCrypto, createInitSpec(dHGroup));
    }

    static BigInteger getQ(DHParameterSpec dHParameterSpec) {
        if (dHParameterSpec instanceof DHDomainParameterSpec) {
            return ((DHDomainParameterSpec) dHParameterSpec).getQ();
        }
        return null;
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public static boolean isGroupSupported(JcaTlsCrypto jcaTlsCrypto, DHGroup dHGroup) {
        return (dHGroup == null || getDHParameterSpec(jcaTlsCrypto, dHGroup) == null) ? false : true;
    }
}