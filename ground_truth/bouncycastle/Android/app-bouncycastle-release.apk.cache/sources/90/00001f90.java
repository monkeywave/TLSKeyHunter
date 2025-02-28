package org.bouncycastle.jcajce.provider.asymmetric;

import java.util.HashMap;
import java.util.Map;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.CompositeSignaturesConstants;
import org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi;
import org.bouncycastle.jcajce.provider.config.ConfigurableProvider;
import org.bouncycastle.jcajce.provider.util.AsymmetricAlgorithmProvider;

/* loaded from: classes2.dex */
public class CompositeSignatures {
    private static final String PREFIX = "org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.";
    private static final Map<String, String> compositesAttributes;

    /* loaded from: classes2.dex */
    public static class Mappings extends AsymmetricAlgorithmProvider {
        @Override // org.bouncycastle.jcajce.provider.util.AlgorithmProvider
        public void configure(ConfigurableProvider configurableProvider) {
            ASN1ObjectIdentifier[] aSN1ObjectIdentifierArr;
            for (ASN1ObjectIdentifier aSN1ObjectIdentifier : CompositeSignaturesConstants.supportedIdentifiers) {
                CompositeSignaturesConstants.CompositeName compositeName = CompositeSignaturesConstants.ASN1IdentifierAlgorithmNameMap.get(aSN1ObjectIdentifier);
                configurableProvider.addAlgorithm("KeyFactory." + compositeName.getId(), "org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyFactorySpi");
                configurableProvider.addAlgorithm("Alg.Alias.KeyFactory", aSN1ObjectIdentifier, compositeName.getId());
                configurableProvider.addAlgorithm("KeyPairGenerator." + compositeName.getId(), "org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.KeyPairGeneratorSpi$" + compositeName);
                configurableProvider.addAlgorithm("Alg.Alias.KeyPairGenerator", aSN1ObjectIdentifier, compositeName.getId());
                configurableProvider.addAlgorithm("Signature." + compositeName.getId(), "org.bouncycastle.jcajce.provider.asymmetric.compositesignatures.SignatureSpi$" + compositeName);
                configurableProvider.addAlgorithm("Alg.Alias.Signature", aSN1ObjectIdentifier, compositeName.getId());
                configurableProvider.addKeyInfoConverter(aSN1ObjectIdentifier, new KeyFactorySpi());
            }
        }
    }

    static {
        HashMap hashMap = new HashMap();
        compositesAttributes = hashMap;
        hashMap.put("SupportedKeyClasses", "org.bouncycastle.jcajce.CompositePublicKey|org.bouncycastle.jcajce.CompositePrivateKey");
        hashMap.put("SupportedKeyFormats", "PKCS#8|X.509");
    }
}