/*
 * Copyright (C) 2018 The ontology Authors
 * This file is part of The ontology library.
 *
 *  The ontology is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  The ontology is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with The ontology.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package com.github.ontid.account;


import com.github.ontid.common.ErrorCode;
import com.github.ontid.crypto.*;
import com.github.ontid.crypto.Base58;
import com.github.ontid.crypto.Digest;
import com.github.ontid.crypto.Signature;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPrivateKey;
import org.bouncycastle.jcajce.provider.asymmetric.ec.BCECPublicKey;
import org.bouncycastle.jcajce.spec.SM2ParameterSpec;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.util.Strings;

import java.io.ByteArrayOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Arrays;


public class Account {
    private KeyType keyType;
    private Object[] curveParams;
    private PrivateKey privateKey;
    private PublicKey publicKey;
    private SignatureScheme signatureScheme;

    // create an account with the specified key type
    public Account(SignatureScheme scheme) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        KeyPairGenerator gen;
        AlgorithmParameterSpec paramSpec;
        signatureScheme = scheme;

        if (scheme == SignatureScheme.SHA256WITHECDSA) {
            this.keyType = KeyType.ECDSA;
            this.curveParams = new Object[]{Curve.P256.toString()};
        } else if (scheme == SignatureScheme.SM3WITHSM2) {
            this.keyType = KeyType.SM2;
            this.curveParams = new Object[]{Curve.SM2P256V1.toString()};
        }

        switch (scheme) {
            case SHA256WITHECDSA:
            case SM3WITHSM2:
                if (!(curveParams[0] instanceof String)) {
                    throw new Exception("InvalidParams");
                }
                String curveName = (String) curveParams[0];
                paramSpec = new ECGenParameterSpec(curveName);
                gen = KeyPairGenerator.getInstance("EC", "BC");
                break;
            default:
                //should not reach here
                throw new Exception(ErrorCode.UnsupportedKeyType);
        }
        gen.initialize(paramSpec, new SecureRandom());
        KeyPair keyPair = gen.generateKeyPair();
        this.privateKey = keyPair.getPrivate();
        this.publicKey = keyPair.getPublic();
    }

    public Account(byte[] prikey, SignatureScheme scheme) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        signatureScheme = scheme;

        if (scheme == SignatureScheme.SM3WITHSM2) {
            this.keyType = KeyType.SM2;
            this.curveParams = new Object[]{Curve.SM2P256V1.toString()};
        } else if (scheme == SignatureScheme.SHA256WITHECDSA) {
            this.keyType = KeyType.ECDSA;
            this.curveParams = new Object[]{Curve.P256.toString()};
        }

        switch (scheme) {
            case SHA256WITHECDSA:
            case SM3WITHSM2:
                BigInteger d = new BigInteger(1, prikey);
                ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec((String) this.curveParams[0]);
                ECParameterSpec paramSpec = new ECNamedCurveSpec(spec.getName(), spec.getCurve(), spec.getG(), spec.getN());
                ECPrivateKeySpec priSpec = new ECPrivateKeySpec(d, paramSpec);
                KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                this.privateKey = kf.generatePrivate(priSpec);

                org.bouncycastle.math.ec.ECPoint Q = spec.getG().multiply(d).normalize();
                if (Q == null || Q.getAffineXCoord() == null || Q.getAffineYCoord() == null) {
                    throw new Exception("normalize error");
                }
                ECPublicKeySpec pubSpec = new ECPublicKeySpec(
                        new ECPoint(Q.getAffineXCoord().toBigInteger(), Q.getAffineYCoord().toBigInteger()),
                        paramSpec);
                this.publicKey = kf.generatePublic(pubSpec);
                break;
            default:
                throw new Exception("Account Error,unsupported key type");
        }
    }

    // construct an account from a serialized pubic key or private key
    public Account(boolean fromPrivate, byte[] pubkey) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        if (fromPrivate) {
            //parsePrivateKey(data);
        } else {
            parsePublicKey(pubkey);
        }
    }

    /**
     * Private Key From WIF
     *
     * @param wif get private from wif
     * @return
     */
    public static byte[] getPrivateKeyFromWIF(String wif) {
        if (wif == null) {
            throw new NullPointerException();
        }
        byte[] data = Base58.decode(wif);
        if (data.length != 38 || data[0] != (byte) 0x80 || data[33] != 0x01) {
            throw new IllegalArgumentException();
        }
        byte[] checksum = Digest.hash256(data, 0, data.length - 4);
        for (int i = 0; i < 4; i++) {
            if (data[data.length - 4 + i] != checksum[i]) {
                throw new IllegalArgumentException();
            }
        }
        byte[] privateKey = new byte[32];
        System.arraycopy(data, 1, privateKey, 0, privateKey.length);
        Arrays.fill(data, (byte) 0);
        return privateKey;
    }

    public SignatureScheme getSignatureScheme() {
        return signatureScheme;
    }

    public KeyType getKeyType() {
        return keyType;
    }

    public Object[] getCurveParams() {
        return curveParams;
    }


    private static byte[] XOR(byte[] x, byte[] y) throws Exception {
        if (x.length != y.length) {
            throw new Exception("ParamError");
        }
        byte[] ret = new byte[x.length];
        for (int i = 0; i < x.length; i++) {
            ret[i] = (byte) (x[i] ^ y[i]);
        }
        return ret;
    }

    public PublicKey getPublicKey() {
        return publicKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public byte[] generateSignature(byte[] msg, SignatureScheme scheme, Object param) throws Exception {
        if (msg == null || msg.length == 0) {
            throw new Exception(ErrorCode.InvalidMessage);
        }
        if (this.privateKey == null) {
            throw new Exception(ErrorCode.WithoutPrivate);
        }
        if (scheme != signatureScheme) {
            throw new Exception(ErrorCode.SignatureSchemeMismatch);
        }
        SignatureHandler ctx = new SignatureHandler(keyType, signatureScheme);
        AlgorithmParameterSpec paramSpec = null;
        if (signatureScheme == SignatureScheme.SM3WITHSM2) {
            if (param instanceof String) {
                paramSpec = new SM2ParameterSpec(Strings.toByteArray((String) param));
            } else if (param == null) {
                paramSpec = new SM2ParameterSpec("1234567812345678".getBytes());
            } else {
                throw new Exception(ErrorCode.InvalidSM2Signature);
            }
        }
        byte[] signature = new Signature(
                signatureScheme,
                paramSpec,
                ctx.generateSignature(privateKey, msg, paramSpec)
        ).toBytes();
        return signature;
    }

    public boolean verifySignature(byte[] msg, byte[] signature) throws Exception {
        if (msg == null || signature == null || msg.length == 0 || signature.length == 0) {
            throw new Exception(ErrorCode.AccountInvalidInput);
        }
        if (this.publicKey == null) {
            throw new Exception(ErrorCode.AccountWithoutPublicKey);
        }
        Signature sig = new Signature(signature);
        SignatureHandler ctx = new SignatureHandler(keyType, sig.getScheme());
        return ctx.verifySignature(publicKey, msg, sig.getValue());
    }

    public byte[] serializePublicKey() {
        ByteArrayOutputStream bs = new ByteArrayOutputStream();
        BCECPublicKey pub = (BCECPublicKey) publicKey;
        try {
            switch (this.keyType) {
                case ECDSA:
                    //bs.write(this.keyType.getLabel());
                    //bs.write(Curve.valueOf(pub.getParameters().getCurve()).getLabel());
                    bs.write(pub.getQ().getEncoded(true));
                    break;
                case SM2:
                    bs.write(this.keyType.getLabel());
                    bs.write(Curve.valueOf(pub.getParameters().getCurve()).getLabel());
                    bs.write(pub.getQ().getEncoded(true));
                    break;
                default:
                    // Should not reach here
                    throw new Exception(ErrorCode.UnknownKeyType);
            }
        } catch (Exception e) {
            // Should not reach here
            e.printStackTrace();
            return null;
        }
        return bs.toByteArray();
    }

    private void parsePublicKey(byte[] data) throws Exception {
        if (data == null) {
            throw new Exception(ErrorCode.NullInput);
        }
        if (data.length < 2) {
            throw new Exception(ErrorCode.InvalidData);
        }
        if (data.length == 33) {
            this.keyType = KeyType.ECDSA;
        } else if (data.length == 35) {
            this.keyType = KeyType.fromLabel(data[0]);
        }
        this.privateKey = null;
        this.publicKey = null;
        switch (this.keyType) {
            case ECDSA:
                this.keyType = KeyType.ECDSA;
                this.curveParams = new Object[]{Curve.P256.toString()};
                ECNamedCurveParameterSpec spec0 = ECNamedCurveTable.getParameterSpec(Curve.P256.toString());
                ECParameterSpec param0 = new ECNamedCurveSpec(spec0.getName(), spec0.getCurve(), spec0.getG(), spec0.getN());
                ECPublicKeySpec pubSpec0 = new ECPublicKeySpec(
                        ECPointUtil.decodePoint(
                                param0.getCurve(),
                                Arrays.copyOfRange(data, 0, data.length)),
                        param0);
                KeyFactory kf0 = KeyFactory.getInstance("EC", "BC");
                this.publicKey = kf0.generatePublic(pubSpec0);
                break;
            case SM2:
//                this.keyType = KeyType.fromLabel(data[0]);
                Curve c = Curve.fromLabel(data[1]);
                this.curveParams = new Object[]{c.toString()};
                ECNamedCurveParameterSpec spec = ECNamedCurveTable.getParameterSpec(c.toString());
                ECParameterSpec param = new ECNamedCurveSpec(spec.getName(), spec.getCurve(), spec.getG(), spec.getN());
                ECPublicKeySpec pubSpec = new ECPublicKeySpec(
                        ECPointUtil.decodePoint(
                                param.getCurve(),
                                Arrays.copyOfRange(data, 2, data.length)),
                        param);
                KeyFactory kf = KeyFactory.getInstance("EC", "BC");
                this.publicKey = kf.generatePublic(pubSpec);
                break;
            default:
                throw new Exception(ErrorCode.UnknownKeyType);
        }
    }

    public byte[] serializePrivateKey() throws Exception {
        switch (this.keyType) {
            case ECDSA:
            case SM2:
                BCECPrivateKey pri = (BCECPrivateKey) this.privateKey;
                String curveName = Curve.valueOf(pri.getParameters().getCurve()).toString();
                byte[] d = new byte[32];
                if (pri.getD().toByteArray().length == 33) {
                    System.arraycopy(pri.getD().toByteArray(), 1, d, 0, 32);
                } else if (pri.getD().toByteArray().length == 31) {
                    d[0] = 0;
                    System.arraycopy(pri.getD().toByteArray(), 0, d, 1, 31);
                } else {
                    return pri.getD().toByteArray();
                }
                return d;
            default:
                // should not reach here
                throw new Exception(ErrorCode.UnknownKeyType);
        }
    }


    public int compareTo(Account o) {
        byte[] pub0 = serializePublicKey();
        byte[] pub1 = o.serializePublicKey();
        for (int i = 0; i < pub0.length && i < pub1.length; i++) {
            if (pub0[i] != pub1[i]) {
                return pub0[i] - pub1[i];
            }
        }

        return pub0.length - pub1.length;
    }

    public String exportWif() throws Exception {
        byte[] data = new byte[38];
        data[0] = (byte) 0x80;
        byte[] prikey = serializePrivateKey();
        System.arraycopy(prikey, 0, data, 1, 32);
        data[33] = (byte) 0x01;
        byte[] checksum = Digest.hash256(data, 0, data.length - 4);
        System.arraycopy(checksum, 0, data, data.length - 4, 4);
        String wif = Base58.encode(data);
        Arrays.fill(data, (byte) 0);
        return wif;
    }
}
