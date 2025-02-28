package org.bouncycastle.asn1.eac;

import java.io.IOException;
import java.util.Enumeration;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1ParsingException;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.util.Arrays;

/* loaded from: classes.dex */
public class CVCertificateRequest extends ASN1Object {
    private static final int bodyValid = 1;
    private static final int signValid = 2;
    private CertificateBody certificateBody;
    private byte[] innerSignature = null;
    private final ASN1TaggedObject original;
    private byte[] outerSignature;

    private CVCertificateRequest(ASN1TaggedObject aSN1TaggedObject) throws IOException {
        this.outerSignature = null;
        this.original = aSN1TaggedObject;
        if (!aSN1TaggedObject.hasTag(64, 7)) {
            initCertBody(aSN1TaggedObject);
            return;
        }
        ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(aSN1TaggedObject.getBaseUniversal(false, 16));
        initCertBody(ASN1TaggedObject.getInstance(aSN1Sequence.getObjectAt(0), 64));
        this.outerSignature = ASN1OctetString.getInstance(ASN1TaggedObject.getInstance(aSN1Sequence.getObjectAt(aSN1Sequence.size() - 1)).getBaseUniversal(false, 4)).getOctets();
    }

    public static CVCertificateRequest getInstance(Object obj) {
        if (obj instanceof CVCertificateRequest) {
            return (CVCertificateRequest) obj;
        }
        if (obj != null) {
            try {
                return new CVCertificateRequest(ASN1TaggedObject.getInstance(obj, 64));
            } catch (IOException e) {
                throw new ASN1ParsingException("unable to parse data: " + e.getMessage(), e);
            }
        }
        return null;
    }

    private void initCertBody(ASN1TaggedObject aSN1TaggedObject) throws IOException {
        if (!aSN1TaggedObject.hasTag(64, 33)) {
            throw new IOException("not a CARDHOLDER_CERTIFICATE in request:" + aSN1TaggedObject.getTagNo());
        }
        Enumeration objects = ASN1Sequence.getInstance(aSN1TaggedObject.getBaseUniversal(false, 16)).getObjects();
        boolean z = false;
        while (objects.hasMoreElements()) {
            ASN1TaggedObject aSN1TaggedObject2 = ASN1TaggedObject.getInstance(objects.nextElement(), 64);
            int tagNo = aSN1TaggedObject2.getTagNo();
            if (tagNo == 55) {
                this.innerSignature = ASN1OctetString.getInstance(aSN1TaggedObject2.getBaseUniversal(false, 4)).getOctets();
                z |= true;
            } else if (tagNo != 78) {
                throw new IOException("Invalid tag, not an CV Certificate Request element:" + aSN1TaggedObject2.getTagNo());
            } else {
                this.certificateBody = CertificateBody.getInstance(aSN1TaggedObject2);
                z |= true;
            }
        }
        if (!z || !true) {
            throw new IOException("Invalid CARDHOLDER_CERTIFICATE in request:" + aSN1TaggedObject.getTagNo());
        }
    }

    public CertificateBody getCertificateBody() {
        return this.certificateBody;
    }

    public byte[] getInnerSignature() {
        return Arrays.clone(this.innerSignature);
    }

    public byte[] getOuterSignature() {
        return Arrays.clone(this.outerSignature);
    }

    public PublicKeyDataObject getPublicKey() {
        return this.certificateBody.getPublicKey();
    }

    public boolean hasOuterSignature() {
        return this.outerSignature != null;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1TaggedObject aSN1TaggedObject = this.original;
        if (aSN1TaggedObject != null) {
            return aSN1TaggedObject;
        }
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(2);
        aSN1EncodableVector.add(this.certificateBody);
        aSN1EncodableVector.add(EACTagged.create(55, this.innerSignature));
        return EACTagged.create(33, new DERSequence(aSN1EncodableVector));
    }
}