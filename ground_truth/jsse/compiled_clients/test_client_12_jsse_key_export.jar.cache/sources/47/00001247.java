package org.openjsse.sun.security.util;

import java.util.Optional;

/* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/RegisteredDomain.class */
public interface RegisteredDomain {

    /* loaded from: test_client_12_jsse_key_export.jar:org/openjsse/sun/security/util/RegisteredDomain$Type.class */
    public enum Type {
        ICANN,
        PRIVATE
    }

    String name();

    Type type();

    String publicSuffix();

    static Optional<RegisteredDomain> from(String domain) {
        return Optional.ofNullable(DomainName.registeredDomain(domain));
    }
}