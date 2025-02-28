package org.bouncycastle.asn1;

import java.io.IOException;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/DLTaggedObjectParser.class */
class DLTaggedObjectParser extends BERTaggedObjectParser {
    private final boolean _constructed;

    /* JADX INFO: Access modifiers changed from: package-private */
    public DLTaggedObjectParser(int i, int i2, boolean z, ASN1StreamParser aSN1StreamParser) {
        super(i, i2, aSN1StreamParser);
        this._constructed = z;
    }

    @Override // org.bouncycastle.asn1.BERTaggedObjectParser
    public boolean isConstructed() {
        return this._constructed;
    }

    @Override // org.bouncycastle.asn1.BERTaggedObjectParser, org.bouncycastle.asn1.InMemoryRepresentable
    public ASN1Primitive getLoadedObject() throws IOException {
        return this._parser.loadTaggedDL(this._tagClass, this._tagNo, this._constructed);
    }

    @Override // org.bouncycastle.asn1.BERTaggedObjectParser, org.bouncycastle.asn1.ASN1TaggedObjectParser
    public ASN1Encodable parseBaseUniversal(boolean z, int i) throws IOException {
        if (!z) {
            return this._constructed ? this._parser.parseImplicitConstructedDL(i) : this._parser.parseImplicitPrimitive(i);
        } else if (this._constructed) {
            return this._parser.parseObject(i);
        } else {
            throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
        }
    }

    @Override // org.bouncycastle.asn1.BERTaggedObjectParser, org.bouncycastle.asn1.ASN1TaggedObjectParser
    public ASN1Encodable parseExplicitBaseObject() throws IOException {
        if (this._constructed) {
            return this._parser.readObject();
        }
        throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
    }

    @Override // org.bouncycastle.asn1.BERTaggedObjectParser, org.bouncycastle.asn1.ASN1TaggedObjectParser
    public ASN1TaggedObjectParser parseExplicitBaseTagged() throws IOException {
        if (this._constructed) {
            return this._parser.parseTaggedObject();
        }
        throw new IOException("Explicit tags must be constructed (see X.690 8.14.2)");
    }

    @Override // org.bouncycastle.asn1.BERTaggedObjectParser, org.bouncycastle.asn1.ASN1TaggedObjectParser
    public ASN1TaggedObjectParser parseImplicitBaseTagged(int i, int i2) throws IOException {
        return 64 == i ? (DLApplicationSpecific) this._parser.loadTaggedDL(i, i2, this._constructed) : new DLTaggedObjectParser(i, i2, this._constructed, this._parser);
    }
}