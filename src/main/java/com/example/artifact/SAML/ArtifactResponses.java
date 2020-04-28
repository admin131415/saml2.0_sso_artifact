package com.example.artifact.SAML;

import com.example.artifact.OpenSAMLUtils;
import com.example.artifact.idp.IDPConstants;
import com.example.artifact.idp.IDPCredentials;
import com.example.artifact.sp.SPConstants;
import com.example.artifact.sp.SPCredentials;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;

import java.io.UnsupportedEncodingException;

public class ArtifactResponses {

    public void verifyAssertionSignature(ArtifactResolve resolve) {

        if (!resolve.isSigned()) {
            throw new RuntimeException("The SAML ArtifactResolve was not signed");
        }

        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(resolve.getSignature());

            SignatureValidator.validate(resolve.getSignature(), SPCredentials.getCredential());

            System.out.println("SAML ArtifactResolve signature verified");
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }



    public ArtifactResponse buildArtifactResponse(Assertion assertion2) throws UnsupportedEncodingException {

        ArtifactResponse artifactResponse = OpenSAMLUtils.buildSAMLObject(ArtifactResponse.class);

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(IDPConstants.IDP_ENTITY_ID);
        artifactResponse.setIssuer(issuer);
        artifactResponse.setIssueInstant(new DateTime());
        artifactResponse.setDestination(SPConstants.ASSERTION_CONSUMER_SERVICE);

        artifactResponse.setID(OpenSAMLUtils.generateSecureRandomId());

        Status status = OpenSAMLUtils.buildSAMLObject(Status.class);
        StatusCode statusCode = OpenSAMLUtils.buildSAMLObject(StatusCode.class);
        statusCode.setValue(StatusCode.SUCCESS);
        status.setStatusCode(statusCode);
        artifactResponse.setStatus(status);

        Response response = OpenSAMLUtils.buildSAMLObject(Response.class);
//        Response response = response;
        response.setDestination(SPConstants.ASSERTION_CONSUMER_SERVICE);
        response.setIssueInstant(new DateTime());
        response.setID(OpenSAMLUtils.generateSecureRandomId());
        Issuer issuer2 = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer2.setValue(IDPConstants.IDP_ENTITY_ID);

        response.setIssuer(issuer2);

        Status status2 = OpenSAMLUtils.buildSAMLObject(Status.class);
        StatusCode statusCode2 = OpenSAMLUtils.buildSAMLObject(StatusCode.class);
        statusCode2.setValue(StatusCode.SUCCESS);
        status2.setStatusCode(statusCode2);

        response.setStatus(status2);

        //artifactResponse.setMessage(response);

        Assertion assertion = assertion2;

        signAssertion(assertion);
        EncryptedAssertion encryptedAssertion = encryptAssertion(assertion);

        response.getEncryptedAssertions().add(encryptedAssertion);
        artifactResponse.setMessage(response);
        System.out.println("artifactResponse=============="+artifactResponse);
        return artifactResponse;
    }
    /**
     * 加密断言
     */
    private EncryptedAssertion encryptAssertion(Assertion assertion) {
        DataEncryptionParameters encryptionParameters = new DataEncryptionParameters();
        encryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
        keyEncryptionParameters.setEncryptionCredential(SPCredentials.getCredential());
        keyEncryptionParameters.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);

        Encrypter encrypter = new Encrypter(encryptionParameters, keyEncryptionParameters);
        encrypter.setKeyPlacement(Encrypter.KeyPlacement.INLINE);

        try {
            return encrypter.encrypt(assertion);
        } catch (EncryptionException e) {
            throw new RuntimeException(e);
        }
    }


    private void signAssertion(Assertion assertion) {
        Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
        signature.setSigningCredential(IDPCredentials.getCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        assertion.setSignature(signature);

        try {
            //noinspection ConstantConditions =》marshall 要求输入Nonnull且输出为Nonull；
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(assertion).marshall(assertion);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }
    }

}
