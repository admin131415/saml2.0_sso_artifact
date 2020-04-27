# saml2.0_sso_artifact
sp向idp以重定向方式发送，idp以artifact绑定方式发送数据通过soap通道

本项目使用工具idea 2019
框架：springBoot

运行起项目后
输入
localhost:8081/home.html
home.html是一个被保护的资源
没有登陆过，重定向到idp
idp登陆成功，生成断言，重定向发送artifact
sp收到artifact生成artifactResolve通过soap发送给idp
idp生成包含真正断言的artifactResponse
