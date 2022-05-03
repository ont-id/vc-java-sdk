package com.github.ontid;

import com.github.ontid.account.Account;
import com.github.ontid.common.Helper;
import com.github.ontid.core.*;
import com.github.ontid.exception.SDKException;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.*;

public class VerifyCredSdk {
    public static final String CRED_DEFAULT_CONTEXT1 = "https://www.w3.org/2018/credentials/v1";
    public static final String CRED_DEFAULT_CONTEXT2 = "https://ont.id/credentials/v1";

    public static final String CRED_DEFAULT_TYPE = "VerifiableCredential";

    public static final String PRESENTATION_DEFAULT_TYPE = "VerifiablePresentation";

    public VerifyCredSdk() {
    }

    // @title    packCredential
    // @description Collect all the information except proofs to form a credential without the Proof field.
    // @param     contexts		[]String		"list of contexts, all of the items are URIs, can be omitted"
    // @param     id	String			"must be a URI, the identifier of new credential, will automatically generate a UUID if it is omitted"
    // @param     type		[]String		"list of types for the expression of type information, all of the items are URIs, can be omitted"
    // @param     credentialSubject	Object		"claims about one or more subjects to be verified by the issuer in JSON format"
    // @param     issuerId		Object		"a URI or an Object to express the issuer information"
    // @param     credentialStatus	CredentialStatus	"a struct that indicates how to deal with the status of this credential"
    // @param     issuanceTime	Date			"date to indicate the issuance time, use current time if it is omitted"
    // @param     expiration	Date			"date to indicate the expiration time, will be a bank if it is omitted"
    // @return    a credential without the proof filed.
    public VerifiableCredential packCredential(String[] context, String id, String[] type, Object credentialSubject, Object issuerId,
                                               CredentialStatus credentialStatus, Date issuanceTime, Date expiration)
            throws SDKException {
        VerifiableCredential vc = new VerifiableCredential(id);
        for (String cont : context) {
            if (!Helper.checkURI(cont)) {
                throw new SDKException("data format not uri");
            }
        }
        if (!Helper.checkURI(id)) {
            throw new SDKException("field not valid");
        }
        if (credentialSubject == null || issuerId == null) {
            throw new SDKException("params can't nil");
        }
        if (!Helper.checkIssuerValid(issuerId) && !Helper.checkCredentialSubject(credentialSubject)) {
            throw new SDKException("issuerId or credentialSubject invalid");
        }
        if (credentialStatus != null) {
            if (!Helper.checkURI(credentialStatus.id)) {
                throw new SDKException("data format not uri");
            }
        }
        vc.credentialStatus = credentialStatus;
        ArrayList<String> wholeContext = new ArrayList<>();
        wholeContext.add(CRED_DEFAULT_CONTEXT1);
        wholeContext.add(CRED_DEFAULT_CONTEXT2);
        if (context != null) {
            wholeContext.addAll(Arrays.asList(context));
        }
        vc.context = new String[]{};
        vc.context = wholeContext.toArray(vc.context);
        ArrayList<String> wholeType = new ArrayList<>();
        wholeType.add(CRED_DEFAULT_TYPE);
        if (type != null) {
            wholeType.addAll(Arrays.asList(type));
        }
        vc.type = new String[]{};
        vc.type = wholeType.toArray(vc.type);
        vc.issuer = issuerId;
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        if (issuanceTime == null) {
            issuanceTime = new Date();
        }
        vc.issuanceDate = formatter.format(issuanceTime);
        if (expiration != null) {
            // check expiration
            if (expiration.before(issuanceTime)) {
                throw new SDKException("cred expired");
            }
            vc.expirationDate = formatter.format(expiration);
        }
        vc.credentialSubject = credentialSubject;
        return vc;
    }

    // @title    packCredentialProof
    // @description   Generate a proof from a credential without proofs. A credential can be attached the issuer's proof to form a verifiable credential.
    // @param     credential	VerifiableCredential	    "a credential need to be attached with the proof field"
    // @param     created		Date			    "date to indicate the creation time, will use the current time if it is omitted"
    // @param     proofPurpose	ProofPurpose			    "the purose of this proof"
    // @param     pubKey		OntIdPubKey		    "the signer's public key"
    // @param     signer		Account	    "the signer's private key"
    // @return    a proof that make the presentation verifiable.
    public Proof packCredentialProof(VerifiableCredential vc, Date created, ProofPurpose proofPurpose, PubKey pubKey, Account signer)
            throws Exception {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        String createdTime = formatter.format(created);
        Proof pf = new Proof(pubKey.id, createdTime, pubKey.type, proofPurpose, "", null);
        vc.proof = pf;
        // generate proof
        byte[] needSignData = vc.genNeedSignData();
        pf.fillHexSignature(signer, needSignData);
        return pf;
    }

    // @title    createVC
    // @description   Generate a verifiable credential using a credential without the proof field and the issuer's proof that make this presentation verifiable.
    // @param     vc	VerifiableCredential	    "a credential need to be attached with the proof field"
    // @param     pf		Proof			    "the issuer's proof"
    // @return    a verifiable credential
    public VerifiableCredential createVC(VerifiableCredential vc, Proof pf) {
        vc.proof = pf;
        return vc;
    }

    // @title    VerifyIssuer
    // @description Verify that a credential's issuer is in the trust list or not
    // @param     vc	VerifiableCredential	    "a verifiable credential to be verified"
    // @param     trustedIssuers	[]String		    "a list of trusted issuers, each item is a URI"
    // @return    true if the issuer is trusted.
    public boolean verifyIssuer(VerifiableCredential vc, String[] trustedIssuers) {
        for (String issuer : trustedIssuers) {
            if (vc.issuer == issuer) {
                return true;
            }
        }
        return false;
    }

    // @title    verifyCredIssuanceDate
    // @description Verify that a credential is effective or not.
    // @param     cred	VerifiableCredential	    "a verifiable credential to be verified"
    // @return    true if the VC is  effective.
    public boolean verifyCredIssuanceDate(VerifiableCredential cred) throws Exception {
        DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date current = new Date();
        if (cred.issuanceDate != null && !cred.issuanceDate.isEmpty()) {
            Date issuanceDate = formatter.parse(cred.issuanceDate);
            return issuanceDate.before(current);
        }
        return true;
    }

    // @title    verifyCredExp
    // @description Verify that a credential is expired or not.
    // @param     cred	VerifiableCredential	    "a verifiable credential to be verified"
    // @return    true if the VC is expired.
    public boolean verifyCredExp(VerifiableCredential cred) throws Exception {
        DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date current = new Date();
        if (cred.expirationDate != null && !cred.expirationDate.isEmpty()) {
            Date expiration = formatter.parse(cred.expirationDate);
            return expiration.after(current);
        }
        return true;
    }

    // @title    verifyCredDate
    // @description Verify that a credential is expired or not.
    // @param     cred	VerifiableCredential	    "a verifiable credential to be verified"
    // @return    false if the VC is expired or issuance data is invalid.
    public boolean verifyCredDate(VerifiableCredential cred) throws Exception {
        DateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date current = new Date();
        if (cred.expirationDate != null && !cred.expirationDate.isEmpty()) {
            Date expiration = formatter.parse(cred.expirationDate);
            if (expiration.before(current)) {
                return false;
            }
        }
        if (cred.issuanceDate != null && !cred.issuanceDate.isEmpty()) {
            Date issuanceDate = formatter.parse(cred.issuanceDate);
            return issuanceDate.before(current);
        }
        return true;
    }

    // @title    verifyProof
    // @description Verify that the proof of a credential is right or not.
    // @param     vc	VerifiableCredential	    "a verifiable credential to be verified"
    // @param     pubKeyHex		String		    "the issuer's public key"
    // @return    true if the issuer's proof is right.
    public boolean verifyProof(VerifiableCredential vc, String pubKeyHex) throws Exception {
        Account account = new Account(false, Helper.hexToBytes(pubKeyHex));
        return account.verifySignature(vc.genNeedSignData(), vc.proof.parseHexSignature());
    }


    // @title    packPresentation
    // @description Collect all the information except proofs to form a presentation without the Proof field.
    // @param     creds	[]VerifiableCredential	"VCs to be presented"
    // @param     id		String			"must be a URI, the identifier of new prestentation, will automatically generate a UUID if it is omitted"
    // @param     context		[]String		"list of contexts, all of the items are URIs, can be omitted"
    // @param     type		[]String		"list of types for the expression of type information, all of the items are URIs, can be omitted"
    // @param     holder		Object		"a URI or an Object to express the holder information, can be omitted"
    // @return    a presentation without the proofs filed.
    public VerifiablePresentation packPresentation(VerifiableCredential[] creds, String id, String[] context,
                                                   String[] type, Object holder)
            throws SDKException {
        if (!Helper.checkURI(id)) {
            throw new SDKException("id not uri format");
        }
        VerifiablePresentation presentation = new VerifiablePresentation(id);
        ArrayList<String> wholeContext = new ArrayList<>();
        wholeContext.add(CRED_DEFAULT_CONTEXT1);
        wholeContext.add(CRED_DEFAULT_CONTEXT2);
        if (context != null) {
            wholeContext.addAll(Arrays.asList(context));
        }
        presentation.context = new String[]{};
        presentation.context = wholeContext.toArray(presentation.context);
        ArrayList<String> wholeType = new ArrayList<>();
        wholeType.add(PRESENTATION_DEFAULT_TYPE);
        if (type != null) {
            wholeType.addAll(Arrays.asList(type));
        }
        presentation.type = new String[]{};
        presentation.type = wholeType.toArray(presentation.type);
        presentation.verifiableCredential = creds;
        presentation.holder = holder;
        return presentation;
    }

    // @title    packPresentationProof
    // @description   Generate a proof from a presentation without proofs. A presentation can be attached with one or more than one proofs.
    // @param     vp	VerifiablePresentation	    "a presentation need to be attached with proofs"
    // @param     created		Date			    "date to indicate the creation time, will use the current time if it is omitted"
    // @param     challenge		String			    "a string that protects against replay attack"
    // @param     domain		Object			    "a string that protects against replay attack"
    // @param     proofPurpose	ProofPurpose			    "the purose of this proof"
    // @param     OntIdPubKey		OntIdPubKey		    "the signer's public key"
    // @param     signer		crypto.PrivateKey	    "the signer's private key"
    // @return    a proof that make the presentation verifiable.
    public Proof packPresentationProof(VerifiablePresentation vp, Date created, String challenge,
                                       Object domain, ProofPurpose proofPurpose, PubKey pk, Account signer)
            throws Exception {
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        String createdTime = formatter.format(created);
        Proof pf = new Proof(pk.id, createdTime, pk.type, proofPurpose, challenge, domain);
        byte[] needSignData = vp.genNeedSignData(pf);
        pf.fillHexSignature(signer, needSignData);
        return pf;
    }

    // @title createVP
    // @description   Generate a verifiable presentation using a presentation without the proof field and a list of proofs that make this presentation verifiable.
    // @param     vp	VerifiablePresentation	    "a presentation need to be attached with proofs"
    // @param     proofs		[]Proof		    "a list of proofs that make this presentation verifiable"
    // @return    a verifiable presentation
    public VerifiablePresentation createVP(VerifiablePresentation vp, Proof[] proofs) {
        vp.proof = proofs;
        return vp;
    }

    // @title verifyPresentationProof
    // @description Verify that the i-th proof of a VP is valid or not
    // @param     vp	VerifiablePresentation	    "a verifiable presentation"
    // @param     index		int			    "the i-th proof of the VP, start from 0"
    // @param     pk		OntIdPubKey		    "the corresponding public key"
    // @return    true if the i-th proof is valid
    public boolean verifyPresentationProof(VerifiablePresentation vp, int index, PubKey pk) throws Exception {
        if (index >= vp.proof.length) {
            throw new Exception("invalid index");
        }

        byte[] needSignData = vp.genNeedSignData(vp.proof[index]);
        Account signer = new Account(false, Helper.hexToBytes(pk.publicKeyHex));
        return signer.verifySignature(needSignData, Helper.hexToBytes(vp.proof[index].hex));
    }

    // @title verifyPresentationCreationTime
    // @description Verify that the i-th proof of a VP is valid or not
    // @param     vp	VerifiablePresentation	    "a verifiable presentation"
    // @param     index		int			    "the i-th proof of the VP, start from 0"
    // @param     expirationTime	Date			    "date that the creation time of VP must be less than it"
    // @return    true if the creation time is acceptable.
    public boolean verifyPresentationCreationTime(VerifiablePresentation vp, int index, Date expirationTime) throws Exception {
        if (index >= vp.proof.length) {
            throw new Exception("invalid index");
        }
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'");
        formatter.setTimeZone(TimeZone.getTimeZone("UTC"));
        Date createdTime = formatter.parse(vp.proof[index].created);
        if (expirationTime.before(createdTime)) {
            return false;
        }
        return true;
    }

}
