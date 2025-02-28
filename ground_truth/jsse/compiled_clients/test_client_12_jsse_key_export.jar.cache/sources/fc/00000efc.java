package org.bouncycastle.util.encoders;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/util/encoders/UrlBase64Encoder.class */
public class UrlBase64Encoder extends Base64Encoder {
    public UrlBase64Encoder() {
        this.encodingTable[this.encodingTable.length - 2] = 45;
        this.encodingTable[this.encodingTable.length - 1] = 95;
        this.padding = (byte) 46;
        initialiseDecodingTable();
    }
}