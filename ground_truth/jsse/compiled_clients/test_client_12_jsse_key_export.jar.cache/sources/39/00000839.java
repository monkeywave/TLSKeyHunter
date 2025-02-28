package org.bouncycastle.jcajce.provider.config;

import java.security.spec.DSAParameterSpec;
import java.util.Map;
import java.util.Set;
import javax.crypto.spec.DHParameterSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/provider/config/ProviderConfiguration.class */
public interface ProviderConfiguration {
    ECParameterSpec getEcImplicitlyCa();

    DHParameterSpec getDHDefaultParameters(int i);

    DSAParameterSpec getDSADefaultParameters(int i);

    Set getAcceptableNamedCurves();

    Map getAdditionalECParameters();
}