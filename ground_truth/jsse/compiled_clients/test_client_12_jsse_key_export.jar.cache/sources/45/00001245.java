package org.openjsse.sun.security.util;

import java.security.InvalidKeyException;
import javax.crypto.SecretKey;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/MessageDigestSpi2.class */
public interface MessageDigestSpi2 {
    void engineUpdate(SecretKey secretKey) throws InvalidKeyException;
}