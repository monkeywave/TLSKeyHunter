package org.openjsse.sun.security.util;

import java.security.InvalidParameterException;
import java.util.regex.PatternSyntaxException;
import javassist.bytecode.Opcode;
import org.bouncycastle.asn1.BERTags;
import sun.security.action.GetPropertyAction;
import sun.security.util.Debug;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/SecurityProviderConstants.class */
public final class SecurityProviderConstants {
    private static final Debug debug = Debug.getInstance("jca", "ProviderConfig");
    public static final int DEF_DSA_KEY_SIZE;
    public static final int DEF_RSA_KEY_SIZE;
    public static final int DEF_RSASSA_PSS_KEY_SIZE;
    public static final int DEF_DH_KEY_SIZE;
    public static final int DEF_EC_KEY_SIZE;
    private static final String KEY_LENGTH_PROP = "jdk.security.defaultKeySize";

    static {
        String keyLengthStr = GetPropertyAction.privilegedGetProperty(KEY_LENGTH_PROP);
        int dsaKeySize = 2048;
        int rsaKeySize = 2048;
        int rsaSsaPssKeySize = 2048;
        int dhKeySize = 2048;
        int ecKeySize = 256;
        if (keyLengthStr != null) {
            try {
                String[] pairs = keyLengthStr.split(",");
                for (String p : pairs) {
                    String[] algoAndValue = p.split(":");
                    if (algoAndValue.length != 2) {
                        if (debug != null) {
                            debug.println("Ignoring invalid pair in jdk.security.defaultKeySize property: " + p);
                        }
                    } else {
                        String algoName = algoAndValue[0].trim().toUpperCase();
                        try {
                            int value = Integer.parseInt(algoAndValue[1].trim());
                            if (algoName.equals("DSA")) {
                                dsaKeySize = value;
                            } else if (algoName.equals("RSA")) {
                                rsaKeySize = value;
                            } else if (algoName.equals("RSASSA-PSS")) {
                                rsaSsaPssKeySize = value;
                            } else if (algoName.equals("DH")) {
                                dhKeySize = value;
                            } else if (algoName.equals("EC")) {
                                ecKeySize = value;
                            } else if (debug != null) {
                                debug.println("Ignoring unsupported algo in jdk.security.defaultKeySize property: " + p);
                            }
                            if (debug != null) {
                                debug.println("Overriding default " + algoName + " keysize with value from " + KEY_LENGTH_PROP + " property: " + value);
                            }
                        } catch (NumberFormatException e) {
                            if (debug != null) {
                                debug.println("Ignoring invalid value in jdk.security.defaultKeySize property: " + p);
                            }
                        }
                    }
                }
            } catch (PatternSyntaxException pse) {
                if (debug != null) {
                    debug.println("Unexpected exception while parsing jdk.security.defaultKeySize property: " + pse);
                }
            }
        }
        DEF_DSA_KEY_SIZE = dsaKeySize;
        DEF_RSA_KEY_SIZE = rsaKeySize;
        DEF_RSASSA_PSS_KEY_SIZE = rsaSsaPssKeySize;
        DEF_DH_KEY_SIZE = dhKeySize;
        DEF_EC_KEY_SIZE = ecKeySize;
    }

    private SecurityProviderConstants() {
    }

    public static final int getDefDSASubprimeSize(int primeSize) {
        if (primeSize <= 1024) {
            return Opcode.IF_ICMPNE;
        }
        if (primeSize == 2048) {
            return BERTags.FLAGS;
        }
        if (primeSize == 3072) {
            return 256;
        }
        throw new InvalidParameterException("Invalid DSA Prime Size: " + primeSize);
    }
}