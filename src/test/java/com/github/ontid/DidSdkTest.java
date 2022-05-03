package com.github.ontid;

import com.github.ontid.account.Account;
import com.github.ontid.common.Helper;
import com.github.ontid.core.*;
import com.github.ontid.crypto.SignatureScheme;
import junit.framework.TestCase;

import java.util.Date;
import java.util.UUID;

public class DidSdkTest extends TestCase {
    VerifyCredSdk sdk = new VerifyCredSdk();

    String[] context = new String[]{};
    String id = "urn:uuid:" + UUID.randomUUID().toString();
    String[] type = new String[]{};
    Object credentialSubject = new Object();
    Object issuerId = "1111";
    CredentialStatus credentialStatus = new CredentialStatus(id, CredentialStatusType.AttestContract);
    Date issuanceTime = new Date();
    Date expiration = new Date();

    Date issuanceTime2 = new Date(System.currentTimeMillis() - 1000000);
    Date expiration2 = new Date(System.currentTimeMillis() - 100000);
    Date expiration3 = new Date(System.currentTimeMillis() - 10000001);

    Date issuanceTime3 = new Date(System.currentTimeMillis() + 1000000);
    Date expiration4 = new Date(System.currentTimeMillis() + 100000000);

    VerifiableCredential vc;
    Date created = new Date();
    Account signer = new Account(SignatureScheme.SHA256WITHECDSA);
    VerifiablePresentation vp;


    PubKey pubKey = new PubKey(id, PubKeyType.EcdsaSecp256k1VerificationKey2019, "", Helper.toHexString(signer.serializePublicKey()));

    Account signer2 = new Account(SignatureScheme.SHA256WITHECDSA);
    PubKey pubKey2 = new PubKey(id, PubKeyType.EcdsaSecp256k1VerificationKey2019, "", Helper.toHexString(signer2.serializePublicKey()));

    public DidSdkTest() throws Exception {
    }

    public void testPackCredential() throws Exception {
        System.out.println("id:" + id);
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
    }

    public void testPackCredentialProof() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        sdk.packCredentialProof(vc, created, ProofPurpose.assertionMethod, pubKey, signer);
    }

    public void testCreateVC() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        Proof proof = sdk.packCredentialProof(vc, created, ProofPurpose.assertionMethod, pubKey, signer);
        sdk.createVC(vc, proof);
    }

    public void testVerifyIssuer() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        boolean boo = sdk.verifyIssuer(vc, new String[]{(String) issuerId});
        System.out.println(boo);
        boo = sdk.verifyIssuer(vc, new String[]{(String) issuerId + "abc"});
        System.out.println(boo);
    }

    public void testVerifyCredDate() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        boolean boo = sdk.verifyCredDate(vc);
        System.out.println(boo);
    }

    public void testVerifyProof() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        Proof proof = sdk.packCredentialProof(vc, created, ProofPurpose.assertionMethod, pubKey, signer);
        sdk.createVC(vc, proof);
        boolean boo = sdk.verifyProof(vc, pubKey.publicKeyHex);
        System.out.println(boo);
    }

    public void testVerifyCredExp() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        boolean boo = sdk.verifyCredExp(vc);
        System.out.println(boo);
    }

    public void testVerifyCredIssuanceDate() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        boolean boo = sdk.verifyCredIssuanceDate(vc);
        assertTrue(boo);
    }

    public void testInvalidIssuanceDate() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime3, expiration4);
        boolean boo = sdk.verifyCredIssuanceDate(vc);
        assertFalse(boo);
    }

    public void testPackPresentation() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        vp = sdk.packPresentation(new VerifiableCredential[]{vc}, id, new String[]{}, new String[]{}, null);
    }

    public void testVerifyPresentationProof() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        vp = sdk.packPresentation(new VerifiableCredential[]{vc}, id, new String[]{}, new String[]{}, null);
        Proof proof = sdk.packPresentationProof(vp, created, "", "", ProofPurpose.assertionMethod, pubKey, signer);
        vp.setProof(new Proof[]{proof});
        boolean boo = sdk.verifyPresentationProof(vp, 0, pubKey);
        assertTrue(boo);
    }

    public void testInvalidSignerProof() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        vp = sdk.packPresentation(new VerifiableCredential[]{vc}, id, new String[]{}, new String[]{}, null);
        Proof proof = sdk.packPresentationProof(vp, created, "", "", ProofPurpose.assertionMethod, pubKey2, signer2);
        vp.setProof(new Proof[]{proof});
        boolean boo = sdk.verifyPresentationProof(vp, 0, pubKey);
        assertFalse(boo);
    }

    public void testInvalidLengthProof() {
        try {
            vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
            vp = sdk.packPresentation(new VerifiableCredential[]{vc}, id, new String[]{}, new String[]{}, null);
            Proof proof = sdk.packPresentationProof(vp, created, "", "", ProofPurpose.assertionMethod, pubKey, signer);
            vp.setProof(new Proof[]{proof});
            boolean boo = false;
            boo = sdk.verifyPresentationProof(vp, 1, pubKey);
            assertTrue(boo);
        } catch (Exception e) {
            assertEquals("invalid index", e.getMessage());
//            e.printStackTrace();
        }
    }


    public void testVerifyPresentationCreationTime() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime, expiration);
        vp = sdk.packPresentation(new VerifiableCredential[]{vc}, id, new String[]{}, new String[]{}, null);
        Proof proof = sdk.packPresentationProof(vp, created, "", "", ProofPurpose.assertionMethod, pubKey, signer);
        vp.setProof(new Proof[]{proof});
        boolean boo = sdk.verifyPresentationCreationTime(vp, 0, expiration);
        assertTrue(boo);
    }

    public void testVerifyPresentationExpirationTime() throws Exception {
        vc = sdk.packCredential(context, id, type, credentialSubject, issuerId, credentialStatus, issuanceTime2, expiration2);
        vp = sdk.packPresentation(new VerifiableCredential[]{vc}, id, new String[]{}, new String[]{}, null);
        Proof proof = sdk.packPresentationProof(vp, created, "", "", ProofPurpose.assertionMethod, pubKey, signer);
        vp.setProof(new Proof[]{proof});
        boolean boo = sdk.verifyPresentationCreationTime(vp, 0, expiration3);
        assertFalse(boo);
    }
}