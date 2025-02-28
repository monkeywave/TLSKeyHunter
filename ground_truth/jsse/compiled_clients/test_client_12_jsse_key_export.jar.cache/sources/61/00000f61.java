package org.openjsse.com.sun.net.ssl;

import java.security.BasicPermission;

@Deprecated
/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/com/sun/net/ssl/SSLPermission.class */
public final class SSLPermission extends BasicPermission {
    private static final long serialVersionUID = -2583684302506167542L;

    public SSLPermission(String name) {
        super(name);
    }

    public SSLPermission(String name, String actions) {
        super(name, actions);
    }
}