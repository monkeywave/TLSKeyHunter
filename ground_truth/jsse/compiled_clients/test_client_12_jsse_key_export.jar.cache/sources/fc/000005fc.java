package org.bouncycastle.crypto.util;

import java.io.IOException;
import java.math.BigInteger;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.nist.NISTNamedCurves;
import org.bouncycastle.asn1.p003x9.ECNamedCurveTable;
import org.bouncycastle.asn1.p003x9.X9ECParameters;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.sec.ECPrivateKey;
import org.bouncycastle.crypto.CryptoServicesRegistrar;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.Strings;

/* loaded from: test_client_12_jsse_key_export.jar:org/bouncycastle/crypto/util/OpenSSHPrivateKeyUtil.class */
public class OpenSSHPrivateKeyUtil {
    static final byte[] AUTH_MAGIC = Strings.toByteArray("openssh-key-v1��");

    private OpenSSHPrivateKeyUtil() {
    }

    public static byte[] encodePrivateKey(AsymmetricKeyParameter asymmetricKeyParameter) throws IOException {
        if (asymmetricKeyParameter == null) {
            throw new IllegalArgumentException("param is null");
        }
        if (!(asymmetricKeyParameter instanceof RSAPrivateCrtKeyParameters) && !(asymmetricKeyParameter instanceof ECPrivateKeyParameters)) {
            if (asymmetricKeyParameter instanceof DSAPrivateKeyParameters) {
                DSAPrivateKeyParameters dSAPrivateKeyParameters = (DSAPrivateKeyParameters) asymmetricKeyParameter;
                DSAParameters parameters = dSAPrivateKeyParameters.getParameters();
                ASN1EncodableVector aSN1EncodableVector = new ASN1EncodableVector();
                aSN1EncodableVector.add(new ASN1Integer(0L));
                aSN1EncodableVector.add(new ASN1Integer(parameters.getP()));
                aSN1EncodableVector.add(new ASN1Integer(parameters.getQ()));
                aSN1EncodableVector.add(new ASN1Integer(parameters.getG()));
                aSN1EncodableVector.add(new ASN1Integer(parameters.getG().modPow(dSAPrivateKeyParameters.getX(), parameters.getP())));
                aSN1EncodableVector.add(new ASN1Integer(dSAPrivateKeyParameters.getX()));
                try {
                    return new DERSequence(aSN1EncodableVector).getEncoded();
                } catch (Exception e) {
                    throw new IllegalStateException("unable to encode DSAPrivateKeyParameters " + e.getMessage());
                }
            } else if (asymmetricKeyParameter instanceof Ed25519PrivateKeyParameters) {
                Ed25519PublicKeyParameters generatePublicKey = ((Ed25519PrivateKeyParameters) asymmetricKeyParameter).generatePublicKey();
                SSHBuilder sSHBuilder = new SSHBuilder();
                sSHBuilder.writeBytes(AUTH_MAGIC);
                sSHBuilder.writeString("none");
                sSHBuilder.writeString("none");
                sSHBuilder.writeString("");
                sSHBuilder.u32(1);
                sSHBuilder.writeBlock(OpenSSHPublicKeyUtil.encodePublicKey(generatePublicKey));
                SSHBuilder sSHBuilder2 = new SSHBuilder();
                int nextInt = CryptoServicesRegistrar.getSecureRandom().nextInt();
                sSHBuilder2.u32(nextInt);
                sSHBuilder2.u32(nextInt);
                sSHBuilder2.writeString("ssh-ed25519");
                byte[] encoded = generatePublicKey.getEncoded();
                sSHBuilder2.writeBlock(encoded);
                sSHBuilder2.writeBlock(Arrays.concatenate(((Ed25519PrivateKeyParameters) asymmetricKeyParameter).getEncoded(), encoded));
                sSHBuilder2.writeString("");
                sSHBuilder.writeBlock(sSHBuilder2.getPaddedBytes());
                return sSHBuilder.getBytes();
            } else {
                throw new IllegalArgumentException("unable to convert " + asymmetricKeyParameter.getClass().getName() + " to openssh private key");
            }
        }
        return PrivateKeyInfoFactory.createPrivateKeyInfo(asymmetricKeyParameter).parsePrivateKey().toASN1Primitive().getEncoded();
    }

    public static AsymmetricKeyParameter parsePrivateKeyBlob(byte[] bArr) {
        AsymmetricKeyParameter asymmetricKeyParameter = null;
        if (bArr[0] == 48) {
            ASN1Sequence aSN1Sequence = ASN1Sequence.getInstance(bArr);
            if (aSN1Sequence.size() == 6) {
                if (allIntegers(aSN1Sequence) && ((ASN1Integer) aSN1Sequence.getObjectAt(0)).getPositiveValue().equals(BigIntegers.ZERO)) {
                    asymmetricKeyParameter = new DSAPrivateKeyParameters(((ASN1Integer) aSN1Sequence.getObjectAt(5)).getPositiveValue(), new DSAParameters(((ASN1Integer) aSN1Sequence.getObjectAt(1)).getPositiveValue(), ((ASN1Integer) aSN1Sequence.getObjectAt(2)).getPositiveValue(), ((ASN1Integer) aSN1Sequence.getObjectAt(3)).getPositiveValue()));
                }
            } else if (aSN1Sequence.size() == 9) {
                if (allIntegers(aSN1Sequence) && ((ASN1Integer) aSN1Sequence.getObjectAt(0)).getPositiveValue().equals(BigIntegers.ZERO)) {
                    RSAPrivateKey rSAPrivateKey = RSAPrivateKey.getInstance(aSN1Sequence);
                    asymmetricKeyParameter = new RSAPrivateCrtKeyParameters(rSAPrivateKey.getModulus(), rSAPrivateKey.getPublicExponent(), rSAPrivateKey.getPrivateExponent(), rSAPrivateKey.getPrime1(), rSAPrivateKey.getPrime2(), rSAPrivateKey.getExponent1(), rSAPrivateKey.getExponent2(), rSAPrivateKey.getCoefficient());
                }
            } else if (aSN1Sequence.size() == 4 && (aSN1Sequence.getObjectAt(3) instanceof ASN1TaggedObject) && (aSN1Sequence.getObjectAt(2) instanceof ASN1TaggedObject)) {
                ECPrivateKey eCPrivateKey = ECPrivateKey.getInstance(aSN1Sequence);
                ASN1ObjectIdentifier aSN1ObjectIdentifier = ASN1ObjectIdentifier.getInstance(eCPrivateKey.getParametersObject());
                asymmetricKeyParameter = new ECPrivateKeyParameters(eCPrivateKey.getKey(), new ECNamedDomainParameters(aSN1ObjectIdentifier, ECNamedCurveTable.getByOID(aSN1ObjectIdentifier)));
            }
        } else {
            SSHBuffer sSHBuffer = new SSHBuffer(AUTH_MAGIC, bArr);
            if (!"none".equals(sSHBuffer.readString())) {
                throw new IllegalStateException("encrypted keys not supported");
            }
            sSHBuffer.skipBlock();
            sSHBuffer.skipBlock();
            if (sSHBuffer.readU32() != 1) {
                throw new IllegalStateException("multiple keys not supported");
            }
            OpenSSHPublicKeyUtil.parsePublicKey(sSHBuffer.readBlock());
            byte[] readPaddedBlock = sSHBuffer.readPaddedBlock();
            if (sSHBuffer.hasRemaining()) {
                throw new IllegalArgumentException("decoded key has trailing data");
            }
            SSHBuffer sSHBuffer2 = new SSHBuffer(readPaddedBlock);
            if (sSHBuffer2.readU32() != sSHBuffer2.readU32()) {
                throw new IllegalStateException("private key check values are not the same");
            }
            String readString = sSHBuffer2.readString();
            if ("ssh-ed25519".equals(readString)) {
                sSHBuffer2.readBlock();
                byte[] readBlock = sSHBuffer2.readBlock();
                if (readBlock.length != 64) {
                    throw new IllegalStateException("private key value of wrong length");
                }
                asymmetricKeyParameter = new Ed25519PrivateKeyParameters(readBlock, 0);
            } else if (readString.startsWith("ecdsa")) {
                ASN1ObjectIdentifier byName = SSHNamedCurves.getByName(Strings.fromByteArray(sSHBuffer2.readBlock()));
                if (byName == null) {
                    throw new IllegalStateException("OID not found for: " + readString);
                }
                X9ECParameters byOID = NISTNamedCurves.getByOID(byName);
                if (byOID == null) {
                    throw new IllegalStateException("Curve not found for: " + byName);
                }
                sSHBuffer2.readBlock();
                asymmetricKeyParameter = new ECPrivateKeyParameters(new BigInteger(1, sSHBuffer2.readBlock()), new ECNamedDomainParameters(byName, byOID));
            }
            sSHBuffer2.skipBlock();
            if (sSHBuffer2.hasRemaining()) {
                throw new IllegalArgumentException("private key block has trailing data");
            }
        }
        if (asymmetricKeyParameter == null) {
            throw new IllegalArgumentException("unable to parse key");
        }
        return asymmetricKeyParameter;
    }

    private static boolean allIntegers(ASN1Sequence aSN1Sequence) {
        for (int i = 0; i < aSN1Sequence.size(); i++) {
            if (!(aSN1Sequence.getObjectAt(i) instanceof ASN1Integer)) {
                return false;
            }
        }
        return true;
    }
}