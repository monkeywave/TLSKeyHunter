package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1ExternalParser.class */
public interface ASN1ExternalParser extends ASN1Encodable, InMemoryRepresentable {
    ASN1Encodable readObject() throws IOException;
}