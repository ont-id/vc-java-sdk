# Verifiable Credential Go SDK

## Class Specification

Currently, this SDK supports the verifiable credentials and presenattions in the format of  `JSON-LD`.

More details can be referred to [the W3C recommendation]laims(https://www.w3.org/TR/vc-data-model/#basic-concepts).

Here we list the classes in this SDK as follows:

### CredentialStatus

[code](./src/main/java/com/github/ontid/core/CredentialStatus.java)

Reference: https://www.w3.org/TR/vc-data-model/#status

There are two type credential status now, `AttestContract` and `RevocationList`.

If `CredentialStatus.type` equals `AttestContract`, `CredentialStatus.id` should be `CredentialRecord` contract address.

### VerifiableCredential

[code](./src/main/java/com/github/ontid/core/VerifiableCredential.java)

Reference: https://www.w3.org/TR/vc-data-model/#basic-concepts

VerifiableCredential.issuer: issuer DID.

#### Proof

[code](./src/main/java/com/github/ontid/core/Proof.java)

Reference: https://www.w3.org/TR/vc-data-model/#proofs-signatures

Proof.type: an instance of `PubKeyType`;

ProofPurpose: only use `assertionMethod` at currently;

Proof.verificationMethod: Public Key URI, for example, `did:ont:AVe4zVZzteo6HoLpdBwpKNtDXLjJBzB9fv#keys-2`;

Proof.hex: hex-encoded signature;

#### VerifiablePresentation

[code](./src/main/java/com/github/ontid/core/VerifiablePresentation.java)

Reference: https://www.w3.org/TR/vc-data-model/#presentations-0

VerifiablePresentation.holder: maybe a DID of String type or an object that has "id" attribute and "id" must be a DID.

### Util Class

There are some utility class.

#### PubKey

[code](./src/main/java/com/github/ontid/core/PubKey.java)

It's a utility class, represent one public key of DIDs.

#### PubKeyType

[code](./src/main/java/com/github/ontid/core/PubKeyType.java)

The supported `pubkey` type.

#### ALG

[code](./src/main/java/com/github/ontid/core/ALG.java)

Each `PubKeyType` has a corresponding `ALG`, each ALG has {algorithm type, curve type, hash method}.

The corresponding relationship is as follows:

| PubKeyType | ALG | Algorithm | Curve | Hash Method |
|------------|-----|-----------|-------|-------------|
| EcdsaSecp224r1VerificationKey2019 | ES224 | ECDSA | P-224 | SHA-224 |
| EcdsaSecp256r1VerificationKey2019 | ES256 | ECDSA | P-256 | SHA-256 |
| EcdsaSecp384r1VerificationKey2019 | ES384 | ECDSA | P-384 | SHA-384 |
| EcdsaSecp521r1VerificationKey2019 | ES512 | ECDSA | P-521 | SHA-512 |
| EcdsaSecp256k1VerificationKey2019 | ES256K | ECDSA | secp256k1 | SHA-256 |
| Ed25519VerificationKey2018 | EdDSA | EDDSA | Curve25519 | SHA-256 |
| SM2VerificationKey2019 | SM | SM2 | SM2P256V1 | SM3 |

#### Util

[code](./src/main/java/com/github/ontid/core/Util.java)

This class Provides some static methods.

### SDK

The VerifyCredSdk class is the main verifiable credentials and presentations class.

#### VerifyCredSdk

[code](./src/main/java/com/github/ontid/core/VerifyCredSdk.java)

The VerifyCredSdk class, all of the functions should have entries here.

## APIs

Here we list the classes in this SDK as follows:

### packCredential

Collect all the information except proofs to form a credential without the Proof field.

1. **public VerifiableCredential packCredential(String[] context, String id, String[] type, Object credentialSubject,
   Object issuerId, CredentialStatus credentialStatus, Date issuanceTime, Date expiration)**
    * contexts: list of contexts, all of the items are URIs, can be omitted
    * id : must be a URI, the identifier of new credential, will automatically generate a UUID if it is omitted
    * type: list of types for the expression of type information, all of the items are URIs, can be omitted
    * credentialSubject:  claims about one or more subjects to be verified by the issuer in JSON format
    * issuer: Id a URI or an Object to express the issuer information
    * credentialStatus : a struct that indicates how to deal with the status of this credential
    * issuanceTime: date to indicate the issuance time, use current time if it is omitted
    * expiration: date to indicate the expiration time, will be a bank if it is omitted
    * return a credential without the proof filed.

### packCredentialProof

Generate a proof from a credential without proofs. A credential can be attached the issuer's proof to form a verifiable
credential.

1. ** public Proof packCredentialProof(VerifiableCredential vc, Date created, ProofPurpose proofPurpose, PubKey pubKey,
   Account signer)
   throws Exception **

    * credential: a credential need to be attached with the proof field
    * created: date to indicate the creation time, will use the current time if it is omitted
    * proofPurpose: the purose of this proof
    * pubKey: the signer's public key
    * signer: the signer's private key
    * return a proof that make the presentation verifiable.

### createVC

Generate a verifiable credential using a credential without the proof field and the issuer's proof that make this
presentation verifiable.

1. **public VerifiableCredential createVC(VerifiableCredential vc, Proof pf)**

    * vc: a credential need to be attached with the proof field
    * pf: the issuer's proof
    * a verifiable credential

### verifyIssuer

Verify that a credential's issuer is in the trust list or not

1. **public boolean verifyIssuer(VerifiableCredential vc, String[] trustedIssuers)**

   * vc: a verifiable credential to be verified
   * trustedIssuer: a list of trusted issuers, each item is a URI
   * return    true if the issuer is trusted.

### verifyCredIssuanceDate

Verify that a credential's issuer is in the trust list or not

1. **public boolean verifyCredIssuanceDate(VerifiableCredential cred) throws Exception**
   * cred: a verifiable credential to be verified
   * return    true if the VC is  effective.

### verifyCredExp

Verify that a credential is expired or not.

1. **public boolean verifyCredExp(VerifiableCredential cred) throws Exception**
   * cred: a verifiable credential to be verified
   * return: true if the VC is expired.

### verifyCredDate

Verify that a credential is expired or not.

1. **public boolean verifyCredDate(VerifiableCredential cred) throws Exception**
   * cred: a verifiable credential to be verified
   * return: false if the VC is expired or issuance data is invalid.

### verifyProof

Verify that the proof of a credential is right or not.

1. **public boolean verifyProof(VerifiableCredential vc, String pubKeyHex) throws Exception**
   * vc	VerifiableCredential: a verifiable credential to be verified
   * pubKeyHex:	the issuer's public key
   * return: true if the issuer's proof is right.

### VerifiablePresentation

Collect all the information except proofs to form a presentation without the Proof field.

1. **public VerifiablePresentation packPresentation(VerifiableCredential[] creds, String id, String[] context,
   String[] type, Object holder)**
   * creds: VCs to be presented
   * id: must be a URI, the identifier of new prestentation, will automatically generate a UUID if it is omitted
   * context: list of contexts, all of the items are URIs, can be omitted
   * type: list of types for the expression of type information, all of the items are URIs, can be omitted
   * holder: a URI or an Object to express the holder information, can be omitted
   * return: a presentation without the proofs filed

### packPresentationProof

Generate a proof from a presentation without proofs. A presentation can be attached with one or more than one proofs.

1. **public Proof packPresentationProof(VerifiablePresentation vp, Date created, String challenge,
   Object domain, ProofPurpose proofPurpose, PubKey pk, Account signer)
   throws Exception**
   * vp: a presentation need to be attached with proofs
   * created: date to indicate the creation time, will use the current time if it is omitted
   * challenge: a string that protects against replay attack
   * domain: a string that protects against replay attack"
   * proofPurpose: the purose of this proof
   * PubKey: the signer's public key
   * signer: the signer's private key
   * return: a proof that make the presentation verifiable.

### createVP

Generate a verifiable presentation using a presentation without the proof field and a list of proofs that make this presentation verifiable.

1. **public VerifiablePresentation createVP(VerifiablePresentation vp, Proof[] proofs)**
   * vp: a presentation need to be attached with proofs
   * proofs: a list of proofs that make this presentation verifiable
   * return: a verifiable presentation

### verifyPresentationProof

Verify that the i-th proof of a VP is valid or not

1. **public boolean verifyPresentationProof(VerifiablePresentation vp, int index, PubKey pk) throws Exception**
   * vp: a verifiable presentation
   * index: the i-th proof of the VP, start from 0
   * pk: the corresponding public key
   * return: true if the i-th proof is valid


### verifyPresentationCreationTime

Verify that the i-th proof of a VP is valid or not

1. **public boolean verifyPresentationCreationTime(VerifiablePresentation vp, int index, Date expirationTime) throws Exception**
   * vp: a verifiable presentation
   * index: the i-th proof of the VP, start from 0
   * expirationTime: date that the creation time of VP must be less than it
   * return: true if the creation time is acceptable
