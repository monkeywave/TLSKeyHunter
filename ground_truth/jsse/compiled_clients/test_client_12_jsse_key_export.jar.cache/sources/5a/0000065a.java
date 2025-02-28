package org.bouncycastle.jcajce.interfaces;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.TBSCertificate;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/jcajce/interfaces/BCX509Certificate.class */
public interface BCX509Certificate {
    X500Name getIssuerX500Name();

    TBSCertificate getTBSCertificateNative();

    X500Name getSubjectX500Name();
}