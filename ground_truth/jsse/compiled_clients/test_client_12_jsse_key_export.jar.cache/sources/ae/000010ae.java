package org.openjsse.sun.security.ssl;

import java.net.InetAddress;
import sun.misc.JavaNetAccess;
import sun.misc.SharedSecrets;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/ssl/HostNameAccessor.class */
public class HostNameAccessor {
    public static String getOriginalHostName(InetAddress inetAddress) {
        JavaNetAccess jna = SharedSecrets.getJavaNetAccess();
        return jna.getOriginalHostName(inetAddress);
    }
}