package com.github.ontid.core;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.annotation.JSONType;
import com.alibaba.fastjson.serializer.SerializerFeature;

import java.util.*;


@JSONType(orders = {"@context", "id", "type", "issuer", "issuanceDate", "expirationDate",
        "credentialSubject", "credentialStatus", "proof"})
public class VerifiableCredential {
    @JSONField(name = "@context")
    public String[] context;
    public String id; // uuid
    public String[] type;
    public Object issuer; // issuer ontId, or an object contains ONTID
    public String issuanceDate;
    public String expirationDate;
    public Object credentialSubject;
    public CredentialStatus credentialStatus;
    public Proof proof; // TODO: support multi

    public static final String CRED_DEFAULT_CONTEXT1 = "https://www.w3.org/2018/credentials/v1";
    public static final String CRED_DEFAULT_CONTEXT2 = "https://ontid.ont.io/credentials/v1";

    public static final String CRED_DEFAULT_TYPE = "VerifiableCredential";

    public VerifiableCredential() {
        this.id = "urn:uuid:" + UUID.randomUUID().toString();
    }

    public VerifiableCredential(String id) {
        if (id == null || "".equals(id)) {
            this.id = "urn:uuid:" + UUID.randomUUID().toString();
        } else {
            this.id = id;
        }
    }

    public byte[] genNeedSignData() {
        Proof proof = this.proof;
        this.proof = this.proof.genNeedSignProof();
        String jsonStr = JSON.toJSONString(this, SerializerFeature.MapSortField);
        this.proof = proof;
        return jsonStr.getBytes();
    }

    public String findSubjectId() {
        return Util.fetchId(credentialSubject);
    }

}
