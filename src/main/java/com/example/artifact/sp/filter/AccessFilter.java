package com.example.artifact.sp.filter;

import com.example.artifact.SAML.SAMLRequest;
import com.example.artifact.sp.SPConstants;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.saml.saml2.core.*;
import org.opensaml.xmlsec.config.impl.JavaCryptoValidationInitializer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Provider;
import java.security.Security;

public class AccessFilter implements Filter {

    private static Logger logger = LoggerFactory.getLogger(AccessFilter.class);

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println("初始化过滤器");
        JavaCryptoValidationInitializer javaCryptoValidationInitializer =
                new JavaCryptoValidationInitializer();
        try {
            //这个方法应该在OpenSAML初始化之前被调用，
            //来确保当前的JCE环境可以符合要求：AES/CBC/ISO10126Padding
            // 对于XML的加密，JCE需要支持ACE（128/256），并使用ISO10126Padding（填充位）
            javaCryptoValidationInitializer.init();
        } catch (InitializationException e) {
            e.printStackTrace();
        }

        //打印当前已经被安装的所有JCE的provider
        for (Provider jceProvider : Security.getProviders()) {
            logger.info(jceProvider.getInfo());
        }
        try {
            logger.info("Initializing");
            //正式初始化ＳＡＭＬ服务
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new RuntimeException("Initialization failed");
        }
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        System.out.println("进入过滤器");
        // 如果用户已经通过身份鉴别，则session中会有AUTHENTICATED_SESSION_ATTRIBUTE，
        // 此时用户是已经被认证的，过滤器应该不对该操作做任何处理；
        if (httpServletRequest.getSession()
                .getAttribute(SPConstants.AUTHENTICATED_SESSION_ATTRIBUTE) != null) {
            chain.doFilter(request, response);
        } else {
            // 反之，则意味着需要开启鉴别流程：保留当前的目标URL，然后重定向到IDP。
            setGotoURLOnSession(httpServletRequest);
            SAMLRequest samlRequest = new SAMLRequest();
            AuthnRequest authnRequest = samlRequest.buildAuthnRequest();
            samlRequest.redirectUserWithRequest(httpServletResponse, authnRequest);
            //重定向
         //   samlRequest.redirectUserWithRequest(httpServletResponse, authnRequest);
        }
    }

    /**
     * 将本来要访问的目标路径保存到Session
     */
    private void setGotoURLOnSession(HttpServletRequest request) {
        request.getSession().setAttribute(SPConstants.GOTO_URL_SESSION_ATTRIBUTE, request.getRequestURL().toString());
    }

    @Override
    public void destroy() {
    }
}
