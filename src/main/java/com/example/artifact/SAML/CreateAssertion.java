package com.example.artifact.SAML;

import com.example.artifact.OpenSAMLUtils;
import com.example.artifact.idp.IDPConstants;
import com.example.artifact.pojo.ArtifactTest;
import com.example.artifact.sp.SPConstants;
import org.apache.commons.codec.digest.DigestUtils;
import org.joda.time.DateTime;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.core.xml.schema.impl.XSStringBuilder;
import org.opensaml.saml.saml2.core.*;

import java.io.UnsupportedEncodingException;
import java.util.Base64;

public class CreateAssertion {
    String artifact;

    public String getArtifact() {
        String artifact1 = artifact;
        return artifact1;
    }


    public Assertion buildAssertion() throws UnsupportedEncodingException {

        Assertion assertion = OpenSAMLUtils.buildSAMLObject(Assertion.class);

        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(IDPConstants.IDP_ENTITY_ID);
        assertion.setIssuer(issuer);
        assertion.setIssueInstant(new DateTime());

        assertion.setID(OpenSAMLUtils.generateSecureRandomId());

        ArtifactTest artifactTest = new ArtifactTest();
        artifactTest.setMessageHandler(DigestUtils.sha1Hex(assertion.getID()));
        artifactTest.setTypeCode("0004");
        artifactTest.setEndpointIndex("0000");
        artifactTest.setSourceId(DigestUtils.sha1Hex(IDPConstants.IDP_ENTITY_ID));
        String artifact1 = "00040000" + artifactTest.getSourceId() + artifactTest.getMessageHandler();

        System.out.println("artifact未经base64编码" + artifact1);

        Base64.Encoder encoder = Base64.getEncoder();
        byte[] textByte = artifact1.getBytes("UTF-8");
        //编码
        artifact = encoder.encodeToString(textByte);

        Subject subject = OpenSAMLUtils.buildSAMLObject(Subject.class);
        assertion.setSubject(subject);

        NameID nameID = OpenSAMLUtils.buildSAMLObject(NameID.class);
        nameID.setFormat(NameIDType.TRANSIENT);
        nameID.setValue("Some NameID value");
        nameID.setSPNameQualifier("SP name qualifier");
        nameID.setNameQualifier("Name qualifier");

        subject.setNameID(nameID);

        subject.getSubjectConfirmations().add(buildSubjectConfirmation());

        assertion.setConditions(buildConditions());

        assertion.getAttributeStatements().add(buildAttributeStatement());

        assertion.getAuthnStatements().add(buildAuthnStatement());

        return assertion;
    }

    private AuthnStatement buildAuthnStatement() {
        AuthnStatement authnStatement = OpenSAMLUtils.buildSAMLObject(AuthnStatement.class);
        AuthnContext authnContext = OpenSAMLUtils.buildSAMLObject(AuthnContext.class);
        AuthnContextClassRef authnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
        authnContextClassRef.setAuthnContextClassRef(AuthnContext.SMARTCARD_AUTHN_CTX);
        authnContext.setAuthnContextClassRef(authnContextClassRef);
        authnStatement.setAuthnContext(authnContext);

        authnStatement.setAuthnInstant(new DateTime());

        return authnStatement;
    }

    private AttributeStatement buildAttributeStatement() {
        AttributeStatement attributeStatement = OpenSAMLUtils.buildSAMLObject(AttributeStatement.class);

        Attribute attributeUserName = OpenSAMLUtils.buildSAMLObject(Attribute.class);

        XSStringBuilder stringBuilder = (XSStringBuilder) XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(XSString.TYPE_NAME);
        assert stringBuilder != null;
        XSString userNameValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        userNameValue.setValue("bob");

        attributeUserName.getAttributeValues().add(userNameValue);
        attributeUserName.setName("username");
        attributeStatement.getAttributes().add(attributeUserName);

        Attribute attributeLevel = OpenSAMLUtils.buildSAMLObject(Attribute.class);
        XSString levelValue = stringBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        levelValue.setValue("999999999");

        attributeLevel.getAttributeValues().add(levelValue);
        attributeLevel.setName("telephone");
        attributeStatement.getAttributes().add(attributeLevel);

        return attributeStatement;

    }

    public Conditions buildConditions() {
        Conditions conditions = OpenSAMLUtils.buildSAMLObject(Conditions.class);
        conditions.setNotBefore(new DateTime().minusDays(2));
        conditions.setNotOnOrAfter(new DateTime().plusDays(2));
        AudienceRestriction audienceRestriction = OpenSAMLUtils.buildSAMLObject(AudienceRestriction.class);
        Audience audience = OpenSAMLUtils.buildSAMLObject(Audience.class);
        audience.setAudienceURI(SPConstants.ASSERTION_CONSUMER_SERVICE);
        audienceRestriction.getAudiences().add(audience);
        conditions.getAudienceRestrictions().add(audienceRestriction);
        return conditions;
    }

    public SubjectConfirmation buildSubjectConfirmation() {
        SubjectConfirmation subjectConfirmation = OpenSAMLUtils.buildSAMLObject(SubjectConfirmation.class);
        subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);

        SubjectConfirmationData subjectConfirmationData = OpenSAMLUtils.buildSAMLObject(SubjectConfirmationData.class);
        subjectConfirmationData.setInResponseTo("Made up ID");
        subjectConfirmationData.setNotBefore(new DateTime().minusDays(2));
        subjectConfirmationData.setNotOnOrAfter(new DateTime().plusDays(2));
        subjectConfirmationData.setRecipient(SPConstants.ASSERTION_CONSUMER_SERVICE);

        subjectConfirmation.setSubjectConfirmationData(subjectConfirmationData);

        return subjectConfirmation;
    }


}
