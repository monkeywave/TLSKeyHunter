package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/BERApplicationSpecificParser.class */
public class BERApplicationSpecificParser extends BERTaggedObjectParser implements ASN1ApplicationSpecificParser {
    /* JADX INFO: Access modifiers changed from: package-private */
    public BERApplicationSpecificParser(int i, ASN1StreamParser aSN1StreamParser) {
        super(64, i, aSN1StreamParser);
    }

    @Override // org.bouncycastle.asn1.ASN1ApplicationSpecificParser
    public ASN1Encodable readObject() throws IOException {
        return parseExplicitBaseObject();
    }
}