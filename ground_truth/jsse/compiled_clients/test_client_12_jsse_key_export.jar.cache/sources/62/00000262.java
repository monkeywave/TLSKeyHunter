package org.bouncycastle.asn1.cryptlib;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/asn1/cryptlib/CryptlibObjectIdentifiers.class */
public class CryptlibObjectIdentifiers {
    public static final ASN1ObjectIdentifier cryptlib = new ASN1ObjectIdentifier("1.3.6.1.4.1.3029");
    public static final ASN1ObjectIdentifier ecc = cryptlib.branch("1").branch("5");
    public static final ASN1ObjectIdentifier curvey25519 = ecc.branch("1");
}