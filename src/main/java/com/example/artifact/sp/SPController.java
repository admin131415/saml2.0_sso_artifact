package com.example.artifact.sp;

import com.example.artifact.SAML.BuildArtifactResolves;
import org.opensaml.saml.saml2.core.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;


@Controller
@RequestMapping("/sp")
public class SPController {

    private static Logger logger = LoggerFactory.getLogger(SPController.class);

    @GetMapping("/consumer")
    public void sso(String SAMLRequest, HttpServletRequest request, HttpServletResponse response) throws Exception {
        System.out.println("到达sp、comsumer");
        logger.info("Artifact received");
        BuildArtifactResolves buildArtifactResolves=new BuildArtifactResolves();

        Artifact artifact = buildArtifactResolves.buildArtifactFromRequest(request);
        logger.info("Artifact: " + artifact.getArtifact());

        //开始创建ArtifactResolve;
        ArtifactResolve artifactResolve =buildArtifactResolves.buildArtifactResolve(artifact);

        //发送ArtifactResolve
        // SOAP消息发送之后，会同步等待Response返回或者超时。
        // 当Response返回时，SAML消息便可或得到：
        ArtifactResponse artifactResponse = buildArtifactResolves.sendAndReceiveArtifactResolve(artifactResolve, response);

        //验证目的地址和有效期；
        buildArtifactResolves.validateDestinationAndLifetime(artifactResponse, request);

        EncryptedAssertion encryptedAssertion = buildArtifactResolves.getEncryptedAssertion(artifactResponse);
        //获得解密后的断言；
        Assertion assertion = buildArtifactResolves.decryptAssertion(encryptedAssertion);
        buildArtifactResolves.verifyAssertionSignature(assertion);

        buildArtifactResolves.logAssertionAttributes(assertion);
        buildArtifactResolves.logAuthenticationInstant(assertion);
        buildArtifactResolves.logAuthenticationMethod(assertion);

        buildArtifactResolves.setAuthenticatedSession(request);
        // 设置302状态码
        response.setStatus(302);
        // 设置location响应头
        response.setHeader("location", "../home.html");
    }

}
