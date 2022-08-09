> Spring Security OAuth2 学习笔记

# 版本说明

JDK17

Spring boot 2.7.2

Spring Authorization Server 0.3.1

Spring Security 5.7.2

# 项目说明

```tex
Spring-Security-OAuth2-Tutorial/
├── LICENSE
├── README.md
├── mvnw
├── mvnw.cmd
├── oauth2-login #OAuth2 Login 登录
├── oauth2-resource #资源服务器
├── oauth2-server #授权服务器
└── pom.xml
```

# 授权服务器

使用Spring Authorization Server 0.3.1实现，使用说明请查看文档

[Git文档](https://github.com/itlab1024/Spring-Security-OAuth2-Tutorial/tree/main/oauth2-server)

[博客文档](https://itlab1024.com/index.php/2022/07/19/spring-authorization-server-0-3-x%e5%ae%9e%e6%88%98/)

# OAuth2 Login

替换项目applicaiton.yaml下的github的client信息（去自己的github设置）

[Git文档](https://github.com/itlab1024/Spring-Security-OAuth2-Tutorial/tree/main/oauth2-login)

[博客文档](https://itlab1024.com/index.php/2022/08/05/spring-security-oauth2-login/)



# 资源服务器

[Github文档](https://github.com/itlab1024/Spring-Security-OAuth2-Tutorial/tree/main/oauth2-resource)
[博客文档](https://itlab1024.com/index.php/2022/08/09/spring-security-oauth2-resource-server/)

# 运行项目

建议使用IDEA工具打开运行。

## 注意事项

修改hosts文件

```tex
127.0.0.1 oauth2server
127.0.0.1 oauth2login
127.0.0.1 resourceserver
```

## 启动方法

* 启动oauth2-sever项目，请注意修改application.yaml下的数据库信息，如果想创建clientId信息，请去测试类里修改并执行。

  ```java
  @Test
  void testSaveClient() {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
      .clientId("itlab1024")
      .clientSecret("{bcrypt}" + new BCryptPasswordEncoder().encode("itlab1024"))
      .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
      .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
      .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
      .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS).redirectUri("http://oauth2login:8000/login/oauth2/code/itlab1024")
      .scope(OidcScopes.OPENID).scope("message.read")
      .scope("message.write")
      .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
      .build();
    registeredClientRepository.save(registeredClient);
  }
  ```

* 启动资源服务器，接下来开始测试登录。具体请查看该项目下的README说明。

* 启动oauth2-login，接下来开始测试登录。具体请查看该项目下的README说明。

  
