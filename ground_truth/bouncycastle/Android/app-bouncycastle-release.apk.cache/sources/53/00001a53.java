package org.bouncycastle.asn1.cms;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1SequenceParser;
import org.bouncycastle.asn1.ASN1SetParser;
import org.bouncycastle.asn1.ASN1TaggedObjectParser;
import org.bouncycastle.asn1.ASN1Util;

/* loaded from: classes.dex */
public class EnvelopedDataParser {
    private ASN1Encodable _nextObject;
    private boolean _originatorInfoCalled;
    private ASN1SequenceParser _seq;
    private ASN1Integer _version;

    public EnvelopedDataParser(ASN1SequenceParser aSN1SequenceParser) throws IOException {
        this._seq = aSN1SequenceParser;
        this._version = ASN1Integer.getInstance(aSN1SequenceParser.readObject());
    }

    public EncryptedContentInfoParser getEncryptedContentInfo() throws IOException {
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }
        ASN1Encodable aSN1Encodable = this._nextObject;
        if (aSN1Encodable != null) {
            this._nextObject = null;
            return new EncryptedContentInfoParser((ASN1SequenceParser) aSN1Encodable);
        }
        return null;
    }

    public OriginatorInfo getOriginatorInfo() throws IOException {
        this._originatorInfoCalled = true;
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }
        ASN1Encodable aSN1Encodable = this._nextObject;
        if (aSN1Encodable instanceof ASN1TaggedObjectParser) {
            ASN1TaggedObjectParser aSN1TaggedObjectParser = (ASN1TaggedObjectParser) aSN1Encodable;
            if (aSN1TaggedObjectParser.hasContextTag(0)) {
                this._nextObject = null;
                return OriginatorInfo.getInstance(((ASN1SequenceParser) aSN1TaggedObjectParser.parseBaseUniversal(false, 16)).getLoadedObject());
            }
        }
        return null;
    }

    public ASN1SetParser getRecipientInfos() throws IOException {
        if (!this._originatorInfoCalled) {
            getOriginatorInfo();
        }
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }
        ASN1SetParser aSN1SetParser = (ASN1SetParser) this._nextObject;
        this._nextObject = null;
        return aSN1SetParser;
    }

    public ASN1SetParser getUnprotectedAttrs() throws IOException {
        if (this._nextObject == null) {
            this._nextObject = this._seq.readObject();
        }
        ASN1Encodable aSN1Encodable = this._nextObject;
        if (aSN1Encodable != null) {
            this._nextObject = null;
            return (ASN1SetParser) ASN1Util.parseContextBaseUniversal((ASN1TaggedObjectParser) aSN1Encodable, 1, false, 17);
        }
        return null;
    }

    public ASN1Integer getVersion() {
        return this._version;
    }
}