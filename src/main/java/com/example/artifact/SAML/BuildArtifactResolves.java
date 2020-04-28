package com.example.artifact.SAML;

import com.example.artifact.OpenSAMLUtils;
import com.example.artifact.idp.IDPConstants;
import com.example.artifact.idp.IDPCredentials;
import com.example.artifact.sp.SPConstants;
import com.example.artifact.sp.SPController;
import com.example.artifact.sp.SPCredentials;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.httpclient.HttpClientBuilder;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.schema.XSString;
import org.opensaml.messaging.context.InOutOperationContext;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.messaging.handler.MessageHandler;
import org.opensaml.messaging.handler.MessageHandlerException;
import org.opensaml.messaging.handler.impl.BasicMessageHandlerChain;
import org.opensaml.messaging.pipeline.httpclient.BasicHttpClientMessagePipeline;
import org.opensaml.messaging.pipeline.httpclient.HttpClientMessagePipeline;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.binding.security.impl.MessageLifetimeSecurityHandler;
import org.opensaml.saml.common.binding.security.impl.ReceivedEndpointSecurityHandler;
import org.opensaml.saml.common.messaging.context.SAMLMessageInfoContext;
import org.opensaml.saml.saml2.binding.decoding.impl.HttpClientResponseSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HttpClientRequestSOAP11Encoder;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.soap.client.http.AbstractPipelineHttpSOAPClient;
import org.opensaml.soap.common.SOAPException;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.keyinfo.impl.StaticKeyInfoCredentialResolver;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.Signer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nonnull;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;

public class BuildArtifactResolves {

    public static Logger logger = LoggerFactory.getLogger(BuildArtifactResolves.class);

    /**SAML消息中有敏感信息
     */
    public Artifact buildArtifactFromRequest(final HttpServletRequest req) {
        Artifact artifact = OpenSAMLUtils.buildSAMLObject(Artifact.class);
        //  artifact.setArtifact("sfwegfdfvregsdfwe");
   //     Artifact artifact2 = Saml2::Type4Artifact.new_from_string(params['SAMLart']);
        artifact.setArtifact(req.getParameter("SAMLart"));
        return artifact;
    }

    public ArtifactResolve buildArtifactResolve(final Artifact artifact) {
        ArtifactResolve artifactResolve = OpenSAMLUtils.buildSAMLObject(ArtifactResolve.class);
        //Issuer：发送方的身份表示，同AuthnRequest中的issuer;
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
        issuer.setValue(SPConstants.SP_ENTITY_ID);
        artifactResolve.setIssuer(issuer);

        //Time of the Request
        artifactResolve.setIssueInstant(new DateTime());
        //ID of the request:
        artifactResolve.setID(OpenSAMLUtils.generateSecureRandomId());
        //destination URL
        artifactResolve.setDestination(IDPConstants.ARTIFACT_RESOLUTION_SERVICE);
        //   artifactResolve.setSignature(new Signature());
        artifactResolve.setArtifact(artifact);
        //sp签名
        Signature signature = OpenSAMLUtils.buildSAMLObject(Signature.class);
        signature.setSigningCredential(SPCredentials.getCredential());
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

        artifactResolve.setSignature(signature);

        try {
            //noinspection ConstantConditions =》marshall 要求输入Nonnull且输出为Nonull；
            XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(artifactResolve).marshall(artifactResolve);
        } catch (MarshallingException e) {
            throw new RuntimeException(e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            throw new RuntimeException(e);
        }

        logger.info("Sending ArtifactResolve");
        logger.info("ArtifactResolve: ");
        OpenSAMLUtils.logSAMLObject(artifactResolve);
        return artifactResolve;
    }

    /**
     * 使用SOAP协议发送 ArtifactResolve
     */
    public ArtifactResponse sendAndReceiveArtifactResolve(final ArtifactResolve artifactResolve) {
        System.out.println("sendAndReceiveArtifactResolve");
        try {

            MessageContext<ArtifactResolve> contextout = new MessageContext<ArtifactResolve>();
            contextout.setMessage(artifactResolve);
            //加入数据签名以增强安全性
            SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
            signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
            signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
            signatureSigningParameters.setSignatureCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);

            SecurityParametersContext securityParametersContext = contextout.getSubcontext(SecurityParametersContext.class, true);
            System.out.println("contextout=============="+contextout.getMessage());
        //    if (securityParametersContext != null) {
                securityParametersContext.setSignatureSigningParameters(signatureSigningParameters);
        //    }

            //创建InOutOperationContext来处理输入输出的信息
            InOutOperationContext<ArtifactResponse, ArtifactResolve> context = new ProfileRequestContext<ArtifactResponse, ArtifactResolve>();
            context.setOutboundMessageContext(contextout);
            context.getSubcontext(SecurityParametersContext.class,true).setSignatureSigningParameters(signatureSigningParameters);
            System.out.println("context.setOutboundMessageContext============"+context.getOutboundMessageContext());
            //为了能发送SOAP消息，还需要设置SOAP Client。
            // 这个Client将会调用消息的处理器，编码器以及解码等来传送消息
            AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject> soapClient = new AbstractPipelineHttpSOAPClient<SAMLObject, SAMLObject>() {
                @Override
                @Nonnull
                protected HttpClientMessagePipeline newPipeline() throws SOAPException {
                    //创建输入输出用的编码器和解码器
                    HttpClientRequestSOAP11Encoder encoder = new HttpClientRequestSOAP11Encoder();
                    HttpClientResponseSOAP11Decoder decoder = new HttpClientResponseSOAP11Decoder();
                    //创建管道
                    BasicHttpClientMessagePipeline pipeline = new BasicHttpClientMessagePipeline(
                            encoder,
                            decoder
                    );
                    //为输出的内容签名
                    //pipeline.setOutboundPayloadHandler(new SAMLOutboundProtocolMessageSigningHandler());
                    return pipeline;
                }};

            // HTTP帮助SOAPClient编码和解码
            HttpClientBuilder clientBuilder = new HttpClientBuilder();
            System.out.println("clientBuilder"+clientBuilder);
            soapClient.setHttpClient(clientBuilder.buildClient());
            soapClient.send(IDPConstants.ARTIFACT_RESOLUTION_SERVICE, context);

            logger.info("ArtifactResponse received");
            logger.info("ArtifactResponse: ");
            OpenSAMLUtils.logSAMLObject(context.getInboundMessageContext().getMessage());

            //当Response返回时，SAML消息便可或得到：
            return context.getInboundMessageContext().getMessage();
        } catch (SecurityException e) {
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        } catch (IllegalAccessException e) {
            throw new RuntimeException(e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

    }

    public EncryptedAssertion getEncryptedAssertion(ArtifactResponse artifactResponse) {
        Response response = (Response)artifactResponse.getMessage();
        return response.getEncryptedAssertions().get(0);
    }

    public void verifyAssertionSignature(Assertion assertion) {

        if (!assertion.isSigned()) {
            throw new RuntimeException("The SAML Assertion was not signed");
        }

        try {
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
            profileValidator.validate(assertion.getSignature());

            SignatureValidator.validate(assertion.getSignature(), IDPCredentials.getCredential());

            logger.info("SAML Assertion signature verified");
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }


    public void validateDestinationAndLifetime(ArtifactResponse artifactResponse, HttpServletRequest request) {

        MessageContext context = new MessageContext<ArtifactResponse>();
        context.setMessage(artifactResponse);

        SAMLMessageInfoContext messageInfoContext = context.getSubcontext(SAMLMessageInfoContext.class, true);
        messageInfoContext.setMessageIssueInstant(artifactResponse.getIssueInstant());

        //生命周期验证，要求SAMLMessageInfoContext包含issue time;
        MessageLifetimeSecurityHandler lifetimeSecurityHandler = new MessageLifetimeSecurityHandler();
        lifetimeSecurityHandler.setClockSkew(1000);
        lifetimeSecurityHandler.setMessageLifetime(2000);
        lifetimeSecurityHandler.setRequiredRule(true);

        //验证消息目的地址，要求base message context包含SAML消息，必需的信息可以从中提取出来
        ReceivedEndpointSecurityHandler receivedEndpointSecurityHandler = new ReceivedEndpointSecurityHandler();
        receivedEndpointSecurityHandler.setHttpServletRequest(request);
        List handlers = new ArrayList<MessageHandler>();
        handlers.add(lifetimeSecurityHandler);
        handlers.add(receivedEndpointSecurityHandler);

        BasicMessageHandlerChain<ArtifactResponse> handlerChain = new BasicMessageHandlerChain<ArtifactResponse>();
        handlerChain.setHandlers(handlers);

        try {
            handlerChain.initialize();
            handlerChain.doInvoke(context);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        } catch (MessageHandlerException e) {
            throw new RuntimeException(e);
        }


    }

    /**
     * 解密断言
     * @param encryptedAssertion 加密的断言
     */
    public Assertion decryptAssertion(EncryptedAssertion encryptedAssertion) {
        StaticKeyInfoCredentialResolver keyInfoCredentialResolver
                = new StaticKeyInfoCredentialResolver(SPCredentials.getCredential());

        Decrypter decrypter = new Decrypter(null,
                keyInfoCredentialResolver,
                new InlineEncryptedKeyResolver());
        decrypter.setRootInNewDocument(true);

        try {
            logger.info("Decrypted Assertion: ");
            OpenSAMLUtils.logSAMLObject(decrypter.decrypt(encryptedAssertion));
            return decrypter.decrypt(encryptedAssertion);
        } catch (DecryptionException e) {
            throw new RuntimeException(e);
        }
    }

    public void logAssertionAttributes(Assertion assertion) {
        for (Attribute attribute : assertion.getAttributeStatements().get(0).getAttributes()) {
            logger.info("Attribute name: " + attribute.getName());
            for (XMLObject attributeValue : attribute.getAttributeValues()) {
                logger.info("Attribute value: " + ((XSString) attributeValue).getValue());
            }
        }
    }

    public void logAuthenticationInstant(Assertion assertion) {
        logger.info("Authentication instant: " + assertion.getAuthnStatements().get(0).getAuthnInstant());
    }

    public void logAuthenticationMethod(Assertion assertion) {
        logger.info("Authentication method: " + assertion.getAuthnStatements().get(0)
                .getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef());
    }

    public void setAuthenticatedSession(HttpServletRequest req) {
        req.getSession().setAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE, true);
    }
}
