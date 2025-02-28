package org.bouncycastle.crypto.util;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.p009x9.X9ECParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.DSAParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;
import org.bouncycastle.crypto.params.ECNamedDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.math.p016ec.ECCurve;

/* loaded from: classes2.dex */
public class OpenSSHPublicKeyUtil {
    private static final String DSS = "ssh-dss";
    private static final String ECDSA = "ecdsa";
    private static final String ED_25519 = "ssh-ed25519";
    private static final String FIDO2_EC_P256 = "sk-ecdsa-sha2-nistp256@openssh.com";
    private static final String FIDO_ED_25519 = "sk-ssh-ed25519@openssh.com";
    private static final String RSA = "ssh-rsa";

    private OpenSSHPublicKeyUtil() {
    }

    public static byte[] encodePublicKey(AsymmetricKeyParameter asymmetricKeyParameter) throws IOException {
        if (asymmetricKeyParameter != null) {
            if (asymmetricKeyParameter instanceof RSAKeyParameters) {
                if (asymmetricKeyParameter.isPrivate()) {
                    throw new IllegalArgumentException("RSAKeyParamaters was for encryption");
                }
                RSAKeyParameters rSAKeyParameters = (RSAKeyParameters) asymmetricKeyParameter;
                SSHBuilder sSHBuilder = new SSHBuilder();
                sSHBuilder.writeString(RSA);
                sSHBuilder.writeBigNum(rSAKeyParameters.getExponent());
                sSHBuilder.writeBigNum(rSAKeyParameters.getModulus());
                return sSHBuilder.getBytes();
            } else if (asymmetricKeyParameter instanceof ECPublicKeyParameters) {
                SSHBuilder sSHBuilder2 = new SSHBuilder();
                ECPublicKeyParameters eCPublicKeyParameters = (ECPublicKeyParameters) asymmetricKeyParameter;
                String nameForParameters = SSHNamedCurves.getNameForParameters(eCPublicKeyParameters.getParameters());
                if (nameForParameters != null) {
                    sSHBuilder2.writeString("ecdsa-sha2-" + nameForParameters);
                    sSHBuilder2.writeString(nameForParameters);
                    sSHBuilder2.writeBlock(eCPublicKeyParameters.getQ().getEncoded(false));
                    return sSHBuilder2.getBytes();
                }
                throw new IllegalArgumentException("unable to derive ssh curve name for " + eCPublicKeyParameters.getParameters().getCurve().getClass().getName());
            } else if (!(asymmetricKeyParameter instanceof DSAPublicKeyParameters)) {
                if (asymmetricKeyParameter instanceof Ed25519PublicKeyParameters) {
                    SSHBuilder sSHBuilder3 = new SSHBuilder();
                    sSHBuilder3.writeString(ED_25519);
                    sSHBuilder3.writeBlock(((Ed25519PublicKeyParameters) asymmetricKeyParameter).getEncoded());
                    return sSHBuilder3.getBytes();
                }
                throw new IllegalArgumentException("unable to convert " + asymmetricKeyParameter.getClass().getName() + " to public key");
            } else {
                DSAPublicKeyParameters dSAPublicKeyParameters = (DSAPublicKeyParameters) asymmetricKeyParameter;
                DSAParameters parameters = dSAPublicKeyParameters.getParameters();
                SSHBuilder sSHBuilder4 = new SSHBuilder();
                sSHBuilder4.writeString(DSS);
                sSHBuilder4.writeBigNum(parameters.getP());
                sSHBuilder4.writeBigNum(parameters.getQ());
                sSHBuilder4.writeBigNum(parameters.getG());
                sSHBuilder4.writeBigNum(dSAPublicKeyParameters.getY());
                return sSHBuilder4.getBytes();
            }
        }
        throw new IllegalArgumentException("cipherParameters was null.");
    }

    public static AsymmetricKeyParameter parsePublicKey(SSHBuffer sSHBuffer) {
        AsymmetricKeyParameter asymmetricKeyParameter;
        String readString = sSHBuffer.readString();
        if (RSA.equals(readString)) {
            asymmetricKeyParameter = new RSAKeyParameters(false, sSHBuffer.readBigNumPositive(), sSHBuffer.readBigNumPositive());
        } else if (DSS.equals(readString)) {
            asymmetricKeyParameter = new DSAPublicKeyParameters(sSHBuffer.readBigNumPositive(), new DSAParameters(sSHBuffer.readBigNumPositive(), sSHBuffer.readBigNumPositive(), sSHBuffer.readBigNumPositive()));
        } else if (readString.startsWith(ECDSA)) {
            String readString2 = sSHBuffer.readString();
            ASN1ObjectIdentifier byName = SSHNamedCurves.getByName(readString2);
            X9ECParameters parameters = SSHNamedCurves.getParameters(byName);
            if (parameters == null) {
                throw new IllegalStateException("unable to find curve for " + readString + " using curve name " + readString2);
            }
            asymmetricKeyParameter = new ECPublicKeyParameters(parameters.getCurve().decodePoint(sSHBuffer.readBlock()), new ECNamedDomainParameters(byName, parameters));
        } else if (readString.equals(FIDO2_EC_P256)) {
            String readString3 = sSHBuffer.readString();
            ASN1ObjectIdentifier byName2 = SSHNamedCurves.getByName(readString3);
            X9ECParameters parameters2 = SSHNamedCurves.getParameters(byName2);
            if (parameters2 == null) {
                throw new IllegalStateException("unable to find curve for " + readString + " using curve name " + readString3);
            }
            ECCurve curve = parameters2.getCurve();
            byte[] readBlock = sSHBuffer.readBlock();
            sSHBuffer.readString();
            asymmetricKeyParameter = new ECPublicKeyParameters(curve.decodePoint(readBlock), new ECNamedDomainParameters(byName2, parameters2));
        } else if (ED_25519.equals(readString)) {
            byte[] readBlock2 = sSHBuffer.readBlock();
            if (readBlock2.length != 32) {
                throw new IllegalStateException("public key value of wrong length");
            }
            asymmetricKeyParameter = new Ed25519PublicKeyParameters(readBlock2, 0);
        } else if (FIDO2_EC_P256.equals(readString)) {
            byte[] readBlock3 = sSHBuffer.readBlock();
            if (readBlock3.length != 32) {
                throw new IllegalStateException("public key value of wrong length");
            }
            sSHBuffer.readString();
            asymmetricKeyParameter = new Ed25519PublicKeyParameters(readBlock3, 0);
        } else {
            asymmetricKeyParameter = null;
        }
        if (asymmetricKeyParameter != null) {
            if (sSHBuffer.hasRemaining()) {
                throw new IllegalArgumentException("decoded key has trailing data");
            }
            return asymmetricKeyParameter;
        }
        throw new IllegalArgumentException("unable to parse key");
    }

    public static AsymmetricKeyParameter parsePublicKey(byte[] bArr) {
        return parsePublicKey(new SSHBuffer(bArr));
    }
}