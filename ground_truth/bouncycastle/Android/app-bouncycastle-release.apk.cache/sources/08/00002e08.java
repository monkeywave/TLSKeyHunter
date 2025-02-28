package org.bouncycastle.tls.crypto.impl.p018bc;

import java.io.IOException;
import java.math.BigInteger;
import kotlin.UByte;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.tls.TlsFatalAlert;
import org.bouncycastle.tls.TlsUtils;
import org.bouncycastle.tls.crypto.TlsCertificate;
import org.bouncycastle.util.Arrays;

/* renamed from: org.bouncycastle.tls.crypto.impl.bc.BcTlsCertificate */
/* loaded from: classes2.dex */
public class BcTlsCertificate extends BcTlsRawKeyCertificate {
    protected final Certificate certificate;

    public BcTlsCertificate(BcTlsCrypto bcTlsCrypto, Certificate certificate) {
        super(bcTlsCrypto, certificate.getSubjectPublicKeyInfo());
        this.certificate = certificate;
    }

    public BcTlsCertificate(BcTlsCrypto bcTlsCrypto, byte[] bArr) throws IOException {
        this(bcTlsCrypto, parseCertificate(bArr));
    }

    public static BcTlsCertificate convert(BcTlsCrypto bcTlsCrypto, TlsCertificate tlsCertificate) throws IOException {
        return tlsCertificate instanceof BcTlsCertificate ? (BcTlsCertificate) tlsCertificate : new BcTlsCertificate(bcTlsCrypto, tlsCertificate.getEncoded());
    }

    public static Certificate parseCertificate(byte[] bArr) throws IOException {
        try {
            return Certificate.getInstance(TlsUtils.readASN1Object(bArr));
        } catch (IllegalArgumentException e) {
            throw new TlsFatalAlert((short) 42, (Throwable) e);
        }
    }

    public Certificate getCertificate() {
        return this.certificate;
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsRawKeyCertificate, org.bouncycastle.tls.crypto.TlsCertificate
    public byte[] getEncoded() throws IOException {
        return this.certificate.getEncoded(ASN1Encoding.DER);
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsRawKeyCertificate, org.bouncycastle.tls.crypto.TlsCertificate
    public byte[] getExtension(ASN1ObjectIdentifier aSN1ObjectIdentifier) throws IOException {
        Extension extension;
        Extensions extensions = this.certificate.getTBSCertificate().getExtensions();
        if (extensions == null || (extension = extensions.getExtension(aSN1ObjectIdentifier)) == null) {
            return null;
        }
        return Arrays.clone(extension.getExtnValue().getOctets());
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsRawKeyCertificate, org.bouncycastle.tls.crypto.TlsCertificate
    public BigInteger getSerialNumber() {
        return this.certificate.getSerialNumber().getValue();
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsRawKeyCertificate, org.bouncycastle.tls.crypto.TlsCertificate
    public String getSigAlgOID() {
        return this.certificate.getSignatureAlgorithm().getAlgorithm().getId();
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsRawKeyCertificate, org.bouncycastle.tls.crypto.TlsCertificate
    public ASN1Encodable getSigAlgParams() {
        return this.certificate.getSignatureAlgorithm().getParameters();
    }

    @Override // org.bouncycastle.tls.crypto.impl.p018bc.BcTlsRawKeyCertificate
    protected boolean supportsKeyUsage(int i) {
        KeyUsage fromExtensions;
        Extensions extensions = this.certificate.getTBSCertificate().getExtensions();
        return extensions == null || (fromExtensions = KeyUsage.fromExtensions(extensions)) == null || ((fromExtensions.getBytes()[0] & UByte.MAX_VALUE) & i) == i;
    }
}