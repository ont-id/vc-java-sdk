package com.github.ontid.core;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.annotation.JSONField;
import com.alibaba.fastjson.annotation.JSONType;
import com.alibaba.fastjson.serializer.SerializerFeature;

import java.util.UUID;

@JSONType(orders = {"@context", "id", "type", "verifiableCredential", "holder", "proof"})
public class VerifiablePresentation {
    @JSONField(name = "@context")
    public String[] context;
    public String id;
    public String[] type;
    public VerifiableCredential[] verifiableCredential;
    public Object holder; // holder may not use
    public Proof[] proof;

    public VerifiablePresentation() {
        this.id = "urn:uuid:" + UUID.randomUUID().toString();
    }

    public VerifiablePresentation(String id) {
        if (id ==null || "".equals(id)) {
            this.id = "urn:uuid:" + UUID.randomUUID().toString();
        }
        this.id = id;
    }

    public void setProof(Proof[] proof) {
        this.proof = proof;
    }

    public byte[] genNeedSignData(Proof needSignProof) {
        Proof[] proofs = this.proof;
        this.proof = new Proof[]{needSignProof.genNeedSignProof()};
        String jsonStr = JSON.toJSONString(this, SerializerFeature.MapSortField);
        this.proof = proofs;
        return jsonStr.getBytes();
    }

    public String fetchHolderOntId() {
        return Util.fetchId(holder);
    }
}
