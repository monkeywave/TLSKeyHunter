package org.openjsse.sun.security.validator;

import java.security.AccessController;
import java.security.PrivilegedAction;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.EnumSet;
import sun.security.util.Debug;
import sun.security.validator.ValidatorException;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/validator/CADistrustPolicy.class */
enum CADistrustPolicy {
    SYMANTEC_TLS { // from class: org.openjsse.sun.security.validator.CADistrustPolicy.1
        @Override // org.openjsse.sun.security.validator.CADistrustPolicy
        void checkDistrust(String variant, X509Certificate[] chain) throws ValidatorException {
            if (!variant.equals(Validator.VAR_TLS_SERVER)) {
                return;
            }
            SymantecTLSPolicy.checkDistrust(chain);
        }
    };
    
    static final EnumSet<CADistrustPolicy> POLICIES = parseProperty();

    /* JADX INFO: Access modifiers changed from: package-private */
    public abstract void checkDistrust(String str, X509Certificate[] x509CertificateArr) throws ValidatorException;

    private static EnumSet<CADistrustPolicy> parseProperty() {
        String property = (String) AccessController.doPrivileged(new PrivilegedAction<String>() { // from class: org.openjsse.sun.security.validator.CADistrustPolicy.2
            /* JADX WARN: Can't rename method to resolve collision */
            @Override // java.security.PrivilegedAction
            public String run() {
                return Security.getProperty("jdk.security.caDistrustPolicies");
            }
        });
        EnumSet<CADistrustPolicy> set = EnumSet.noneOf(CADistrustPolicy.class);
        if (property == null || property.isEmpty()) {
            return set;
        }
        String[] policies = property.split(",");
        for (String policy : policies) {
            String policy2 = policy.trim();
            try {
                CADistrustPolicy caPolicy = (CADistrustPolicy) Enum.valueOf(CADistrustPolicy.class, policy2);
                set.add(caPolicy);
            } catch (IllegalArgumentException e) {
                Debug debug = Debug.getInstance("certpath");
                if (debug != null) {
                    debug.println("Unknown value for the jdk.security.caDistrustPolicies property: " + policy2);
                }
            }
        }
        return set;
    }
}