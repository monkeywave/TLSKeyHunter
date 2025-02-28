package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1ApplicationSpecificParser.class */
public interface ASN1ApplicationSpecificParser extends ASN1TaggedObjectParser {
    ASN1Encodable readObject() throws IOException;
}