package org.bouncycastle.crypto.constraints;

import java.util.Set;
import java.util.logging.Level;
import org.bouncycastle.crypto.CryptoServiceProperties;

/* loaded from: classes2.dex */
public class LoggingConstraint extends ServicesConstraint {
    protected LoggingConstraint(Set<String> set) {
        super(set);
    }

    @Override // org.bouncycastle.crypto.CryptoServicesConstraints
    public void check(CryptoServiceProperties cryptoServiceProperties) {
        if (!isException(cryptoServiceProperties.getServiceName()) && LOG.isLoggable(Level.INFO)) {
            LOG.info("service " + cryptoServiceProperties.getServiceName() + " referenced [" + cryptoServiceProperties.getServiceName() + ", " + cryptoServiceProperties.bitsOfSecurity() + ", " + cryptoServiceProperties.getPurpose());
        }
    }
}