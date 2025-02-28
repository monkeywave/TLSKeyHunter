package org.bouncycastle.tls;

/* JADX INFO: Access modifiers changed from: package-private */
/* loaded from: classes2.dex */
public class TlsServerCertificateImpl implements TlsServerCertificate {
    protected Certificate certificate;
    protected CertificateStatus certificateStatus;

    /* JADX INFO: Access modifiers changed from: package-private */
    public TlsServerCertificateImpl(Certificate certificate, CertificateStatus certificateStatus) {
        this.certificate = certificate;
        this.certificateStatus = certificateStatus;
    }

    @Override // org.bouncycastle.tls.TlsServerCertificate
    public Certificate getCertificate() {
        return this.certificate;
    }

    @Override // org.bouncycastle.tls.TlsServerCertificate
    public CertificateStatus getCertificateStatus() {
        return this.certificateStatus;
    }
}