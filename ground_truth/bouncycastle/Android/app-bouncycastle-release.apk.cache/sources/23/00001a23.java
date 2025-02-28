package org.bouncycastle.asn1.cmp;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Util;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

/* loaded from: classes.dex */
public class KemOtherInfo extends ASN1Object {
    private static final PKIFreeText DEFAULT_staticString = new PKIFreeText("CMP-KEM");

    /* renamed from: ct */
    private final ASN1OctetString f241ct;
    private final ASN1Integer len;
    private final AlgorithmIdentifier mac;
    private final ASN1OctetString recipNonce;
    private final ASN1OctetString senderNonce;
    private final PKIFreeText staticString;
    private final ASN1OctetString transactionID;

    public KemOtherInfo(ASN1OctetString aSN1OctetString, ASN1OctetString aSN1OctetString2, ASN1OctetString aSN1OctetString3, long j, AlgorithmIdentifier algorithmIdentifier, ASN1OctetString aSN1OctetString4) {
        this(aSN1OctetString, aSN1OctetString2, aSN1OctetString3, new ASN1Integer(j), algorithmIdentifier, aSN1OctetString4);
    }

    public KemOtherInfo(ASN1OctetString aSN1OctetString, ASN1OctetString aSN1OctetString2, ASN1OctetString aSN1OctetString3, ASN1Integer aSN1Integer, AlgorithmIdentifier algorithmIdentifier, ASN1OctetString aSN1OctetString4) {
        this.staticString = DEFAULT_staticString;
        this.transactionID = aSN1OctetString;
        this.senderNonce = aSN1OctetString2;
        this.recipNonce = aSN1OctetString3;
        this.len = aSN1Integer;
        this.mac = algorithmIdentifier;
        this.f241ct = aSN1OctetString4;
    }

    private KemOtherInfo(ASN1Sequence aSN1Sequence) {
        int i;
        ASN1OctetString aSN1OctetString;
        ASN1OctetString aSN1OctetString2;
        ASN1Primitive tryGetContextBaseUniversal;
        ASN1Primitive tryGetContextBaseUniversal2;
        ASN1Primitive tryGetContextBaseUniversal3;
        if (aSN1Sequence.size() < 4 || aSN1Sequence.size() > 7) {
            throw new IllegalArgumentException("sequence size should be between 4 and 7 inclusive");
        }
        PKIFreeText pKIFreeText = PKIFreeText.getInstance(aSN1Sequence.getObjectAt(0));
        this.staticString = pKIFreeText;
        PKIFreeText pKIFreeText2 = DEFAULT_staticString;
        if (!pKIFreeText2.equals(pKIFreeText)) {
            throw new IllegalArgumentException("staticString field should be " + pKIFreeText2);
        }
        ASN1TaggedObject tryGetTagged = tryGetTagged(aSN1Sequence, 1);
        ASN1OctetString aSN1OctetString3 = null;
        if (tryGetTagged == null || (tryGetContextBaseUniversal3 = ASN1Util.tryGetContextBaseUniversal(tryGetTagged, 0, true, 4)) == null) {
            i = 1;
            aSN1OctetString = null;
        } else {
            aSN1OctetString = (ASN1OctetString) tryGetContextBaseUniversal3;
            tryGetTagged = tryGetTagged(aSN1Sequence, 2);
            i = 2;
        }
        if (tryGetTagged == null || (tryGetContextBaseUniversal2 = ASN1Util.tryGetContextBaseUniversal(tryGetTagged, 1, true, 4)) == null) {
            aSN1OctetString2 = null;
        } else {
            aSN1OctetString2 = (ASN1OctetString) tryGetContextBaseUniversal2;
            i++;
            tryGetTagged = tryGetTagged(aSN1Sequence, i);
        }
        if (tryGetTagged != null && (tryGetContextBaseUniversal = ASN1Util.tryGetContextBaseUniversal(tryGetTagged, 2, true, 4)) != null) {
            aSN1OctetString3 = (ASN1OctetString) tryGetContextBaseUniversal;
            i++;
            tryGetTagged = tryGetTagged(aSN1Sequence, i);
        }
        if (tryGetTagged != null) {
            throw new IllegalArgumentException("unknown tag: " + ASN1Util.getTagText(tryGetTagged));
        }
        this.transactionID = aSN1OctetString;
        this.senderNonce = aSN1OctetString2;
        this.recipNonce = aSN1OctetString3;
        this.len = ASN1Integer.getInstance(aSN1Sequence.getObjectAt(i));
        this.mac = AlgorithmIdentifier.getInstance(aSN1Sequence.getObjectAt(i + 1));
        this.f241ct = ASN1OctetString.getInstance(aSN1Sequence.getObjectAt(i + 2));
        if (i + 3 != aSN1Sequence.size()) {
            throw new IllegalArgumentException("unexpected data at end of sequence");
        }
    }

    private static void addOptional(ASN1EncodableVector aSN1EncodableVector, int i, ASN1Encodable aSN1Encodable) {
        if (aSN1Encodable != null) {
            aSN1EncodableVector.add(new DERTaggedObject(true, i, aSN1Encodable));
        }
    }

    public static KemOtherInfo getInstance(Object obj) {
        if (obj instanceof KemOtherInfo) {
            return (KemOtherInfo) obj;
        }
        if (obj != null) {
            return new KemOtherInfo(ASN1Sequence.getInstance(obj));
        }
        return null;
    }

    private static ASN1TaggedObject tryGetTagged(ASN1Sequence aSN1Sequence, int i) {
        ASN1Encodable objectAt = aSN1Sequence.getObjectAt(i);
        if (objectAt instanceof ASN1TaggedObject) {
            return (ASN1TaggedObject) objectAt;
        }
        return null;
    }

    public ASN1OctetString getCt() {
        return this.f241ct;
    }

    public ASN1Integer getLen() {
        return this.len;
    }

    public AlgorithmIdentifier getMac() {
        return this.mac;
    }

    public ASN1OctetString getRecipNonce() {
        return this.recipNonce;
    }

    public ASN1OctetString getSenderNonce() {
        return this.senderNonce;
    }

    public ASN1OctetString getTransactionID() {
        return this.transactionID;
    }

    @Override // org.bouncycastle.asn1.ASN1Object, org.bouncycastle.asn1.ASN1Encodable
    public ASN1Primitive toASN1Primitive() {
        ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector(7);
        aSN1EncodableVector.add(this.staticString);
        addOptional(aSN1EncodableVector, 0, this.transactionID);
        addOptional(aSN1EncodableVector, 1, this.senderNonce);
        addOptional(aSN1EncodableVector, 2, this.recipNonce);
        aSN1EncodableVector.add(this.len);
        aSN1EncodableVector.add(this.mac);
        aSN1EncodableVector.add(this.f241ct);
        return new DERSequence(aSN1EncodableVector);
    }
}