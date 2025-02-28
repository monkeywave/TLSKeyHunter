package org.bouncycastle.asn1;

import java.io.IOException;
import java.io.InputStream;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1BitStringParser.class */
public interface ASN1BitStringParser extends ASN1Encodable, InMemoryRepresentable {
    InputStream getBitStream() throws IOException;

    InputStream getOctetStream() throws IOException;

    int getPadBits();
}