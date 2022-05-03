package com.github.ontid.core;

public class PubKey {
    public String id; // pubkey URI
    public PubKeyType type; // pubkey type, for example: EcdsaSecp256r1VerificationKey2019
    public String controller;
    public String publicKeyHex;

    public PubKey(String id, // pubkey URI
                  PubKeyType type, // pubkey type, for example: EcdsaSecp256r1VerificationKey2019
                  String controller,
                  String publicKeyHex) {
        this.id = id;
        this.type = type;
        this.controller = controller;
        this.publicKeyHex = publicKeyHex;
    }
}
