package com.example.artifact.idp;


import com.example.artifact.OpenSAMLUtils;
import com.example.artifact.SAML.ArtifactResponses;
import com.example.artifact.SAML.CreateAssertion;
import com.example.artifact.pojo.ArtifactTest;
import com.example.artifact.sp.SPConstants;
import com.example.artifact.sp.SPCredentials;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import net.shibboleth.utilities.java.support.xml.BasicParserPool;

import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.decoder.MessageDecodingException;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.saml2.binding.decoding.impl.HTTPSOAP11Decoder;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPSOAP11Encoder;
import org.opensaml.saml.saml2.core.*;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;



@Controller
@RequestMapping("/idp")
public class IdpController {
    @Autowired
    private SamlRequestCache samlRequestCache;

    @GetMapping("/sso")
    public void sso(String SAMLRequest, HttpServletRequest request, HttpServletResponse response) throws Exception {
        System.out.println("进入idp   controller");
        /**
         * 是否在idp端已登录
         */
        Cookie[] cookies = request.getCookies();
        String cookie_value = null;
        if (cookies != null) {
            System.out.println("在idp端已登录");
            for (Cookie cookie : cookies) {
                if (IDPConstants.IDP_COOKIE_KEY.equalsIgnoreCase(cookie.getName())) {
                    cookie_value = cookie.getValue();
                }
            }
        }
        if (cookie_value != null && IDPConstants.IDP_COOKIE_VALUE.equalsIgnoreCase(cookie_value)) {
            //已登录，解析SAMLRequest对象,查找出用户信息
          /*  String email = "test@qq.com";
            AuthnRequestField authnRequestField = authnRequestHandler.handleAuthnRequest(SAMLRequest);
            String result = samlResponseGenerator.generateSamlResponse(email,authnRequestField);
            response.reset();
            PrintWriter printWriter = response.getWriter();
            printWriter.write( samlResponseGenerator.getForm(authnRequestField.getAssertionConsumerServiceUrl(), new Base64().encodeAsString(result.getBytes("utf-8"))));
            printWriter.flush();
            printWriter.close();*/
            return;
        } else {
            System.out.println("//重定向到登陆页面");
            //重定向到登陆页面 ?SAMLRequest=" + SAMLRequest
            samlRequestCache.setSAMLRequest(SAMLRequest);
            System.out.println("SAMLRequest()=========" + samlRequestCache.getSAMLRequest());
            // response.sendRedirect("/login.html");
            // 设置302状态码
            response.setStatus(302);
            // 设置location响应头
            response.setHeader("location", "../login.html?SAMLRequest=" + SAMLRequest);
            // 注意：一次重定向，向服务器发送两次请求
            System.out.println(response.getHeader("location"));
            return;
        }
    }

    Assertion assertion2;

    @PostMapping("/auth")
    public void login(String username, String password, HttpServletRequest req, HttpServletResponse res) throws Exception {
        System.out.println("认证密码");
        if ("admin".equals(username) && "admin".equals(password)) {
            System.out.println("idp认证用户成功");

            CreateAssertion createAssertion = new CreateAssertion();

            Assertion assertion = createAssertion.buildAssertion();

            assertion2 = assertion;
            //res.sendRedirect(SPConstants.ASSERTION_CONSUMER_SERVICE + "?SAMLart=MDAwNDAwMDBjZGZiNDlmNjcwNDBkEyODQ0ZGMxNmIzNGMxMGFjODhjZW0MjEyYTM0ZjE0ZQ==");

            res.sendRedirect(SPConstants.ASSERTION_CONSUMER_SERVICE + "?SAMLart="+ createAssertion.getArtifact());
        }
    }


    @PostMapping("/artifact")
    public void artifact(String SAMLRequest, HttpServletRequest req, HttpServletResponse resp) throws Exception {
        System.out.println("/artifact");

        HTTPSOAP11Decoder decoder = new HTTPSOAP11Decoder();

        decoder.setHttpServletRequest(req);

        try {
            BasicParserPool parserPool = new BasicParserPool();
            parserPool.initialize();
            decoder.setParserPool(parserPool);
            decoder.initialize();
            decoder.decode();
        } catch (MessageDecodingException e) {
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

        OpenSAMLUtils.logSAMLObject(decoder.getMessageContext().getMessage());
        ArtifactResponses artifactResponses = new ArtifactResponses();
        ArtifactResponse artifactResponse = artifactResponses.buildArtifactResponse(assertion2);

        MessageContext<SAMLObject> context = new MessageContext<SAMLObject>();
        context.setMessage(artifactResponse);

        HTTPSOAP11Encoder encoder = new HTTPSOAP11Encoder();
        encoder.setMessageContext(context);
        encoder.setHttpServletResponse(resp);
        try {
            encoder.prepareContext();
            encoder.initialize();
            encoder.encode();
        } catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }

    }
}
