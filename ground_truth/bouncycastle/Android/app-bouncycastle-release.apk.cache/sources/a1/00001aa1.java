package org.bouncycastle.asn1.dvcs;

import org.bouncycastle.asn1.ASN1Choice;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ocsp.CertID;
import org.bouncycastle.asn1.ocsp.CertStatus;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.smime.SMIMECapabilities;
import org.bouncycastle.asn1.x509.Certificate;
import org.bouncycastle.asn1.x509.CertificateList;
import org.bouncycastle.asn1.x509.Extension;

/* loaded from: classes.dex */
public class CertEtcToken extends ASN1Object implements ASN1Choice {
    public static final int TAG_ASSERTION = 3;
    public static final int TAG_CAPABILITIES = 8;
    public static final int TAG_CERTIFICATE = 0;
    public static final int TAG_CRL = 4;
    public static final int TAG_ESSCERTID = 1;
    public static final int TAG_OCSPCERTID = 6;
    public static final int TAG_OCSPCERTSTATUS = 5;
    public static final int TAG_OCSPRESPONSE = 7;
    public static final int TAG_PKISTATUS = 2;
    private static final boolean[] explicit = {false, true, false, true, false, true, false, false, true};
    private Extension extension;
    private int tagNo;
    private ASN1Encodable value;

    public CertEtcToken(int i, ASN1Encodable aSN1Encodable) {
        this.tagNo = i;
        this.value = aSN1Encodable;
    }

    private CertEtcToken(ASN1TaggedObject aSN1TaggedObject) {
        ASN1Encodable certificate;
        int tagNo = aSN1TaggedObject.getTagNo();
        this.tagNo = tagNo;
        switch (tagNo) {
            case 0:
                certificate = Certificate.getInstance(aSN1TaggedObject, false);
                break;
            case 1:
                certificate = ESSCertID.getInstance(aSN1TaggedObject.getExplicitBaseObject());
                break;
            case 2:
                certificate = PKIStatusInfo.getInstance(aSN1TaggedObject, false);
                break;
            case 3:
                certificate = ContentInfo.getInstance(aSN1TaggedObject.getExplicitBaseObject());
                break;
            case 4:
                certificate = CertificateList.getInstance(aSN1TaggedObject, false);
                break;
            case 5:
                certificate = CertStatus.getInstance(aSN1TaggedObject.getExplicitBaseObject());
                break;
            case 6:
                certificate = CertID.getInstance(aSN1TaggedObject, false);
                break;
            case 7:
                certificate = OCSPResponse.getInstance(aSN1TaggedObject, false);
                break;
            case 8:
                certificate = SMIMECapabilities.getInstance(aSN1TaggedObject.getExplicitBaseObject());
                break;
            default:
                throw new IllegalArgumentException("Unknown tag: " + this.tagNo);
        }
        this.value = certificate;
    }

    public CertEtcToken(Extension extension) {
        this.tagNo = -1;
        this.extension = extension;
    }

    public static CertEtcToken[] arrayFromSequence(ASN1Sequence aSN1Sequence) {
        int size = aSN1Sequence.size();
        CertEtcToken[] certEtcTokenArr = new CertEtcToken[size];
        for (int i = 0; i != size; i++) {
            certEtcTokenArr[i] = getInstance(aSN1Sequence.getObjectAt(i));
        }
        return certEtcTokenArr;
    }

    public static CertEtcToken getInstance(Object obj) {
        if (obj instanceof CertEtcToken) {
            return (CertEtcToken) obj;
        }
        if (obj instanceof ASN1TaggedObject) {
            return new CertEtcToken(ASN1TaggedObject.getInstance(obj, 128));
        }
        if (obj != null) {
            return new CertEtcToken(Extension.getInstance(obj));
        }
        return null;
    }

    public Extension getExtension() {
        return this.extension;
    }

    public int getTagNo() {
        return this.tagNo;
    }

    public ASN1Encodable getValue() {
        return this.value;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        Extension extension = this.extension;
        if (extension == null) {
            boolean[] zArr = explicit;
            int i = this.tagNo;
            return new DERTaggedObject(zArr[i], i, this.value);
        }
        return extension.toASN1Primitive();
    }

    public String toString() {
        return "CertEtcToken {\n" + this.value + "}\n";
    }
}