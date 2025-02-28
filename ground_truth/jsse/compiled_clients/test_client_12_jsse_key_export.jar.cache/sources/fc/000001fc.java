package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/ASN1TaggedObjectParser.class */
public interface ASN1TaggedObjectParser extends ASN1Encodable, InMemoryRepresentable {
    int getTagClass();

    int getTagNo();

    boolean hasContextTag(int i);

    boolean hasTag(int i, int i2);

    ASN1Encodable getObjectParser(int i, boolean z) throws IOException;

    ASN1Encodable parseBaseUniversal(boolean z, int i) throws IOException;

    ASN1Encodable parseExplicitBaseObject() throws IOException;

    ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException;

    ASN1TaggedObjectParser parseImplicitBaseTagged(int i, int i2) throws IOException;
}