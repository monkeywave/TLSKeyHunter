package org.bouncycastle.tls;

/* loaded from: classes2.dex */
public interface TlsServerCertificate {
    Certificate getCertificate();

    CertificateStatus getCertificateStatus();
}