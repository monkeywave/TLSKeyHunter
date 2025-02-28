package org.bouncycastle.asn1;

import java.io.InputStream;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1OctetStringParser.class */
public interface ASN1OctetStringParser extends ASN1Encodable, InMemoryRepresentable {
    InputStream getOctetStream();
}