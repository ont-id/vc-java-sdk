package com.github.ontid.core;

import com.alibaba.fastjson.annotation.JSONType;
import com.github.ontid.account.Account;
import com.github.ontid.common.Helper;


@JSONType(orders = {"type", "created", "challenge", "domain", "proofPurpose", "verificationMethod", "hex"})
public class Proof {
    public PubKeyType type;
    public String created; // time stamp
    public String challenge;
    public Object domain;
    public ProofPurpose proofPurpose;
    public String verificationMethod; // pubkey uri
    public String hex;

    public Proof() {
    }

    public Proof(String publicKeyURI, String created, PubKeyType type, ProofPurpose proofPurpose) {
        this.type = type;
        this.created = created;
        if (proofPurpose == null) {
            proofPurpose = ProofPurpose.assertionMethod;
        }
        this.proofPurpose = proofPurpose;
        this.verificationMethod = publicKeyURI;
    }

    public Proof(String publicKeyURI, String created, PubKeyType type, ProofPurpose proofPurpose,
                 String challenge, Object domain) {
        this(publicKeyURI, created, type, proofPurpose);
        this.challenge = challenge;
        this.domain = domain;
    }

    public Proof genNeedSignProof() {
        return new Proof(verificationMethod, created, type, proofPurpose, challenge, domain);
    }

    public void fillHexSignature(Account account, byte[] needSignData) throws Exception {
        byte[] sig = account.generateSignature(needSignData, account.getSignatureScheme(), null);
        hex = Helper.toHexString(sig);
    }

    public byte[] parseHexSignature() {
        return Helper.hexToBytes(hex);
    }
}
