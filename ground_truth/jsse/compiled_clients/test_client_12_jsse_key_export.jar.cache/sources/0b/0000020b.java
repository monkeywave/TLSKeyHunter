package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/BERApplicationSpecific.class */
public class BERApplicationSpecific extends ASN1ApplicationSpecific {
    public BERApplicationSpecific(int i, ASN1Encodable aSN1Encodable) throws IOException {
        this(true, i, aSN1Encodable);
    }

    public BERApplicationSpecific(boolean z, int i, ASN1Encodable aSN1Encodable) throws IOException {
        super(new BERTaggedObject(z, 64, i, aSN1Encodable));
    }

    public BERApplicationSpecific(int i, ASN1EncodableVector aSN1EncodableVector) {
        super(new BERTaggedObject(false, 64, i, (ASN1Encodable) BERFactory.createSequence(aSN1EncodableVector)));
    }

    /* JADX INFO: Access modifiers changed from: package-private */
    public BERApplicationSpecific(ASN1TaggedObject aSN1TaggedObject) {
        super(aSN1TaggedObject);
    }
}