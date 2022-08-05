# 说明

`Spring Authorization Server` 遵循[Oauth2.1](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-v2-1-05)和[OpenID Connect 1.0](https://openid.net/specs/openid-connect-core-1_0.html)，它建立在`Spring Security`之上。

# 最小化项目

## 创建项目

要求JDK11以上

使用Idea创建一个Maven的Spring Boot(笔者使用的是`spring boot 2.7`)项目

pom需要引入`Authorization Server的配置`

```xml
<dependency>
    <groupId>org.springframework.security</groupId>
    <artifactId>spring-security-oauth2-authorization-server</artifactId>
    <version>0.3.1</version>
</dependency>
```

完整的pom.xml文件如下：

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>2.7.0</version>
        <relativePath/> <!-- lookup parent from repository -->
    </parent>
    <groupId>com.itlab1024</groupId>
    <artifactId>Spring_Authorization_Server_0_3_x</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>Spring-Authorization-Server-0.3.0</name>
    <description>Spring-Authorization-Server-0.3.0</description>
    <properties>
        <java.version>17</java.version>
    </properties>
    <dependencies>
        <!-- 必须引入-->
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-authorization-server</artifactId>
            <version>0.3.1</version>
        </dependency>
        <!-- 必须引入-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <!-- 可选引入-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        <!-- 可选引入-->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```



## 配置

使用`@Bean`和`@Configuration`创建配置，这是官方推荐的最小配置。

```java
package com.itlab1024.base;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    /**
     * 这是个Spring security 的过滤器链，默认会配置
     * <p>
     * OAuth2 Authorization endpoint
     * <p>
     * OAuth2 Token endpoint
     * <p>
     * OAuth2 Token Introspection endpoint
     * <p>
     * OAuth2 Token Revocation endpoint
     * <p>
     * OAuth2 Authorization Server Metadata endpoint
     * <p>
     * JWK Set endpoint
     * <p>
     * OpenID Connect 1.0 Provider Configuration endpoint
     * <p>
     * OpenID Connect 1.0 UserInfo endpoint
     * 这些协议端点，只有配置了他才能够访问的到接口地址（类似mvc的controller）。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http)
            throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        http
                // Redirect to the login page when not authenticated from the
                // authorization endpoint
                .exceptionHandling((exceptions) -> exceptions
                        .authenticationEntryPoint(
                                new LoginUrlAuthenticationEntryPoint("/login"))
                );

        return http.build();
    }

    /**
     * 这个也是个Spring Security的过滤器链，用于Spring Security的身份认证。
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * 配置用户信息，或者配置用户数据来源，主要用于用户的检索。
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }

    /**
     * oauth2 用于第三方认证，RegisteredClientRepository 主要用于管理第三方（每个第三方就是一个客户端）
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * 用于给access_token签名使用。
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成秘钥对，为jwkSource提供服务。
     * @return
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }

    /**
     * 配置Authorization Server实例
     * @return
     */
    @Bean
    public ProviderSettings providerSettings() {
        return ProviderSettings.builder().build();
    }
}

```

至此最小化项目完成，这就能够完成oauth2的授权。

## 测试

### 授权码模式

浏览器访问   http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read&redirect_uri=http://127.0.0.1:8080/authorized

> 需要注意的是`redirect_uri`必须是`RegisteredClient`实例设置的。

![授权码模式登录界面](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231150833.png)

输入用户名(user)密码(password）后

![授权界面](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231151478.png)



提交后，会自动跳转到`redirect_uri`地址，并且地址会紧跟着`code`。

![redirect_uri回调后携带code字段](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231151774.png)



返回的code是

```tex
axia5-kuIIzO1D1eu1V_02KawWIkRydiZrDEPAtLhNlYC7kLeUazD_bh5UXGQVJj7W2gxC1zpQJuQ2D9ZVrQyVfufxMYyv4fkjjMitiQ1gH-bGQ6KqGy5egeC15NfHBt
```

接下来需要使用这个`code`获取token（我用postman请求）。

#### 获取token

授权码获取token的请求地址是`oauth2/token`，post请求：

![请求体](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231151778.png)

上线这个三个参数是必须的，并且要跟代码中设置完全一直，另外获取token要传递client_id和client_secret参数，默认不支持使用表单传递，要通过header传递。比如在postman中

![通过header传递client_id和client_secret](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231152534.png)

其实上线的操作实际上就是在header中传递了一个header，key=Authorization， value是client_id:client_secret，然后使用base64加密的字符串,然后前面加上`Basic `(注意后面有空格)。对于我这个例子来说就是`Basic bWVzc2FnaW5nLWNsaWVudDpzZWNyZXQ=`

返回结果是：

```json
{
    "access_token": "eyJraWQiOiIxNGMxOTM5Yy02YzcxLTQ1MGMtOTg4OS1jOTdiNjM5NTE3ZmEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1NDMyMzg0OSwic2NvcGUiOlsibWVzc2FnZS5yZWFkIl0sImlzcyI6Imh0dHA6XC9cLzEyNy4wLjAuMTo4MDgwIiwiZXhwIjoxNjU0MzI0MTQ5LCJpYXQiOjE2NTQzMjM4NDl9.r6KSDrVbd65n_KRC2SnOH93nGYnoP2uWZwyiamke5PGWa72OHPxgwktgAxK0gHIjQ_sgh5tD4R2swb9bARIn2ZvUb3DtIXpLzEoCGRu4DqJoaUFnj71oAvX1MSruHeLqQaCwL2nJ-C-TNwj_mFHzcZFdaFZRQIIIkaG46Zgj1G0BCxpKtJy3FVIcbGJK-HYHHdh2XOMAIyCA5MrDn2VtZmJDwSbhSSEdU8jY8n41LPUd79koozIH_6onrx-y9ly3-evV3cAGBvsWA26h6PAR0Nxv47LXaUM5Hn_6OA20noCi53CC0qdahRJSs9eHpXsLd0rpjPDrk4nK9S7G0wTIlw",
    "refresh_token": "2CvlhRXdg6EK0ZzS_3kI-AI-AeCXBFpvD1krSbu28sTundjXnwvZT4AuQ03rtUr5TD2VFUWyuAJ68fAmNIonUVSRaDKzdx-Z2Z61np_HlcBF2iUxLRyl4JW9jeBQ7CZG",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 299
}
```

#### 刷新token

![刷新token请求方式](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231152083.png)

结果是：

```json
{
    "access_token": "eyJraWQiOiIxNGMxOTM5Yy02YzcxLTQ1MGMtOTg4OS1jOTdiNjM5NTE3ZmEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1NDMyNDU1OCwic2NvcGUiOlsibWVzc2FnZS5yZWFkIl0sImlzcyI6Imh0dHA6XC9cLzEyNy4wLjAuMTo4MDgwIiwiZXhwIjoxNjU0MzI0ODU4LCJpYXQiOjE2NTQzMjQ1NTh9.pOsWaoBrNrJyGTYOyvlN1d4FrKjpo2PxRIi7SHLfYjQ0xuqnuYaqPVOhs8rw9VN1hhjpl1d59RixOXkOAIK6PUI_-y_6MTmXL71YZ1lmrifhZ24bYkqXQKMAsbFvj3bXn6RyVnTwFsiy9IzZBRK_-PTPWQd9DbaYkmpryeZtGBqUFYAyBDrgCTYgw0SEoDI2qEX_W3Bgxiz9yTDH5Gszdbe0CzxvHP7LOGDi7-q-WziGhQCoMfFMK0P2WvzeAagseUEUpoSJTk8IMh-_8EgatrwilSYjkKKwgf_-hd9UXDi4bsW9MNA9iIDCYqKJ5dflTutoUJX8oxpnYTwP8iGNDA",
    "refresh_token": "2CvlhRXdg6EK0ZzS_3kI-AI-AeCXBFpvD1krSbu28sTundjXnwvZT4AuQ03rtUr5TD2VFUWyuAJ68fAmNIonUVSRaDKzdx-Z2Z61np_HlcBF2iUxLRyl4JW9jeBQ7CZG",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 299
}
```

### 简化模式

在oauth2.1中被移除







### 客户端模式

#### 获取token

![客户端模式获取access_token](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231152276.png)

结果是：

```json
{
    "access_token": "eyJraWQiOiIxNGMxOTM5Yy02YzcxLTQ1MGMtOTg4OS1jOTdiNjM5NTE3ZmEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZXNzYWdpbmctY2xpZW50IiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1NDMyNDc5Nywic2NvcGUiOlsib3BlbmlkIiwibWVzc2FnZS5yZWFkIiwibWVzc2FnZS53cml0ZSJdLCJpc3MiOiJodHRwOlwvXC8xMjcuMC4wLjE6ODA4MCIsImV4cCI6MTY1NDMyNTA5NywiaWF0IjoxNjU0MzI0Nzk3fQ.CMWqUxhjOlYzg6SY5uKkWIQDy96XV559TmG2YHZYlwe08a6u7xrwEm_b9m3rd9-QqkQpuxbFBD_o4dk3wl7PKVlZuWNCVrcvEXMFREexU6wwKtzTWKTBWYtDOAvKJN81iJ34UqsXRQ_M3xvUlpVXMjFKY9c3hsP9te8FpfcMi4IZfnHS79CunTh7tgovEo53nu9UNQ2qKy_MR9a13cXpe_AepOP_68gaLO-SAdRI-H9L4e57Y3w7Lq-UWUxywtnAtEcnm_PTGaA-gIEvCiN0rx6pZFBOxv-58OhNfp79oTN33yBDN-E3dSWgioQDp-Sc7kIb8z-rzXa1ZQgx19xTGg",
    "scope": "openid message.read message.write",
    "token_type": "Bearer",
    "expires_in": 299
}
```



客户端模式没有刷新token模式。



### 密码模式

在oauth2.1中被移除

> 以上是最小化示例，我上传到了github，地址是：https://github.com/ITLab1024/Spring-Authorization-Server-0.3.0， 标签是：v1.0.0



# 配置

## 默认配置

之前已经通过最小配置，完成了一个`Spring Authorization Server`项目，本章学习下关于配置的内容。

`Spring Authorization Server`还提供了一种实现最小配置的默认配置形式。就是通过`OAuth2AuthorizationServerConfiguration`这个类。

看下这个类的源码：

```java
/*
 * Copyright 2020-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.config.annotation.web.configuration;

import java.util.HashSet;
import java.util.Set;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSKeySelector;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.RequestMatcher;

/**
 * {@link Configuration} for OAuth 2.0 Authorization Server support.
 *
 * @author Joe Grandja
 * @since 0.0.1
 * @see OAuth2AuthorizationServerConfigurer
 */
@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServerConfiguration {

   @Bean
   @Order(Ordered.HIGHEST_PRECEDENCE)
   public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
      applyDefaultSecurity(http);
      return http.build();
   }

   // @formatter:off
   public static void applyDefaultSecurity(HttpSecurity http) throws Exception {
      OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
            new OAuth2AuthorizationServerConfigurer<>();
      RequestMatcher endpointsMatcher = authorizationServerConfigurer
            .getEndpointsMatcher();

      http
         .requestMatcher(endpointsMatcher)
         .authorizeRequests(authorizeRequests ->
            authorizeRequests.anyRequest().authenticated()
         )
         .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
         .apply(authorizationServerConfigurer);
   }
   // @formatter:on

   public static JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
      Set<JWSAlgorithm> jwsAlgs = new HashSet<>();
      jwsAlgs.addAll(JWSAlgorithm.Family.RSA);
      jwsAlgs.addAll(JWSAlgorithm.Family.EC);
      jwsAlgs.addAll(JWSAlgorithm.Family.HMAC_SHA);
      ConfigurableJWTProcessor<SecurityContext> jwtProcessor = new DefaultJWTProcessor<>();
      JWSKeySelector<SecurityContext> jwsKeySelector =
            new JWSVerificationKeySelector<>(jwsAlgs, jwkSource);
      jwtProcessor.setJWSKeySelector(jwsKeySelector);
      // Override the default Nimbus claims set verifier as NimbusJwtDecoder handles it instead
      jwtProcessor.setJWTClaimsSetVerifier((claims, context) -> {
      });
      return new NimbusJwtDecoder(jwtProcessor);
   }

   @Bean
   RegisterMissingBeanPostProcessor registerMissingBeanPostProcessor() {
      RegisterMissingBeanPostProcessor postProcessor = new RegisterMissingBeanPostProcessor();
      postProcessor.addBeanDefinition(ProviderSettings.class, () -> ProviderSettings.builder().build());
      return postProcessor;
   }

}
```

这里注入一个叫做`authorizationServerSecurityFilterChain`的bean，这跟我之前最小化项目时实现的基本是相同的。

有了这个bean，就会支持如下协议端点：

- [OAuth2 Authorization endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-authorization-endpoint)
- [OAuth2 Token endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-token-endpoint)
- [OAuth2 Token Introspection endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-token-introspection-endpoint)
- [OAuth2 Token Revocation endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-token-revocation-endpoint)
- [OAuth2 Authorization Server Metadata endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oauth2-authorization-server-metadata-endpoint)
- [JWK Set endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#jwk-set-endpoint)
- [OpenID Connect 1.0 Provider Configuration endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oidc-provider-configuration-endpoint)
- [OpenID Connect 1.0 UserInfo endpoint](https://docs.spring.io/spring-authorization-server/docs/current/reference/html/protocol-endpoints.html#oidc-user-info-endpoint)

接来我我尝试使用`OAuth2AuthorizationServerConfiguration`这个类来实现一个`Authorization Server`。

> 本次我会将 Spring Security和Authorization Server的配置分开

Spring Security 使用 `SecurityConfig`  类，创建一个新的`Authorization Server`配置类 `AuthorizationServerConfig`。



SecurityConfig类配置如下：

```java
package com.itlab1024.base;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    /**
     * 这个也是个Spring Security的过滤器链，用于Spring Security的身份认证。
     *
     * @param http
     * @return
     * @throws Exception
     */
    @Bean
    @Order(2)
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .anyRequest().authenticated()
                )
                // Form login handles the redirect to the login page from the
                // authorization server filter chain
                .formLogin(Customizer.withDefaults());

        return http.build();
    }

    /**
     * 配置用户信息，或者配置用户数据来源，主要用于用户的检索。
     *
     * @return
     */
    @Bean
    public UserDetailsService userDetailsService() {
        UserDetails userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();

        return new InMemoryUserDetailsManager(userDetails);
    }
}
```

代码如下：

```java
package com.itlab1024.base;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

@Configuration
@Import(OAuth2AuthorizationServerConfiguration.class)
public class AuthorizationServerConfig {

    /**
     * oauth2 用于第三方认证，RegisteredClientRepository 主要用于管理第三方（每个第三方就是一个客户端）
     *
     * @return
     */
    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID)
                .scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();

        return new InMemoryRegisteredClientRepository(registeredClient);
    }

    /**
     * 用于给access_token签名使用。
     *
     * @return
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        KeyPair keyPair = generateRsaKey();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAKey rsaKey = new RSAKey.Builder(publicKey)
                .privateKey(privateKey)
                .keyID(UUID.randomUUID().toString())
                .build();
        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    /**
     * 生成秘钥对，为jwkSource提供服务。
     *
     * @return
     */
    private static KeyPair generateRsaKey() {
        KeyPair keyPair;
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            keyPair = keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
        return keyPair;
    }
}
```

至此可以实现了`Authorization Server`。

测试客户端调用。

![客户端模式](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231152396.png)

授权码模式测试

![授权码模式](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231152428.png)



![获取code](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231152090.png)



![授权码模式-获取token](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231152412.png)

授权码模式也没有问题。



## 存储配置

`Spring Authorization Server`默认是支持内存和JDBC两种存储模式的，内存模式只适合开发和简单的测试。接下来我们来实现JDBC存储方式。

修改步骤如下：

1. 引入JDBC相关依赖。

2. 创建数据库并初始化表，以及在`application.yaml`文件中配置数据库连接。

3. 修改`Spring Security`和`Spring authorization Server`的配置。
3. 初始化表数据
3. 测试服务

接下来我依次实现。

1. 引入JDBC相关依赖

```xml
<dependency>
  <groupId>org.springframework.boot</groupId>
  <artifactId>spring-boot-starter-jdbc</artifactId>
</dependency>
<dependency>
  <groupId>org.postgresql</groupId>
  <artifactId>postgresql</artifactId>
  <scope>runtime</scope>
</dependency>
```

2. 创建数据库并初始化表，以及在`application.yaml`文件中配置数据库连接。

```mysql
create table oauth2_authorization
(
    id                            varchar(100)  not null
        primary key,
    registered_client_id          varchar(100)  not null,
    principal_name                varchar(200)  not null,
    authorization_grant_type      varchar(100)  not null,
    attributes                    blob          null,
    state                         varchar(500)  null,
    authorization_code_value      blob          null,
    authorization_code_issued_at  timestamp     null,
    authorization_code_expires_at timestamp     null,
    authorization_code_metadata   blob          null,
    access_token_value            blob          null,
    access_token_issued_at        timestamp     null,
    access_token_expires_at       timestamp     null,
    access_token_metadata         blob          null,
    access_token_type             varchar(100)  null,
    access_token_scopes           varchar(1000) null,
    oidc_id_token_value           blob          null,
    oidc_id_token_issued_at       timestamp     null,
    oidc_id_token_expires_at      timestamp     null,
    oidc_id_token_metadata        blob          null,
    refresh_token_value           blob          null,
    refresh_token_issued_at       timestamp     null,
    refresh_token_expires_at      timestamp     null,
    refresh_token_metadata        blob          null
);

create table oauth2_authorization_consent
(
    registered_client_id varchar(100)  not null,
    principal_name       varchar(200)  not null,
    authorities          varchar(1000) not null,
    primary key (registered_client_id, principal_name)
);

create table oauth2_registered_client
(
    id                            varchar(100)                        not null
        primary key,
    client_id                     varchar(100)                        not null,
    client_id_issued_at           timestamp default CURRENT_TIMESTAMP not null,
    client_secret                 varchar(200)                        null,
    client_secret_expires_at      timestamp                           null,
    client_name                   varchar(200)                        not null,
    client_authentication_methods varchar(1000)                       not null,
    authorization_grant_types     varchar(1000)                       not null,
    redirect_uris                 varchar(1000)                       null,
    scopes                        varchar(1000)                       not null,
    client_settings               varchar(2000)                       not null,
    token_settings                varchar(2000)                       not null
);

create table users
(
    username varchar(50)  not null
        primary key,
    password varchar(500) not null,
    enabled  tinyint(1)   not null
);

create table authorities
(
    username  varchar(50) not null,
    authority varchar(50) not null,
    constraint ix_auth_username
        unique (username, authority),
    constraint fk_authorities_users
        foreign key (username) references users (username)
);
```

初始化表，建表语句在哪里？

`Spring Security`的建表语句在

```
org/springframework/security/core/userdetails/jdbc/users.ddl
```

`Spring authorization Server`的建表文件在：

```
org/springframework/security/oauth2/server/authorization/oauth2-authorization-consent-schema.sql

org/springframework/security/oauth2/server/authorization/oauth2-authorization-schema.sql

org/springframework/security/oauth2/server/authorization/client/oauth2-registered-client-schema.sql
```

都在jar包中，并且sql可能会有问题，请大家根据自己使用的数据库进行修改。

**配置文件中配置数据库连接信息**

```yaml
server:
  port: 8080
spring:
  main:
    allow-bean-definition-overriding: true
  datasource:
    url: jdbc:mysql://localhost:3306/spring-authorization-server
    driver-class-name: com.mysql.cj.jdbc.Driver
    username: root
    password: qwe!@#123
```

请根据自己的情况进行修改。



3. 修改`Spring Security`和`Spring authorization Server`的配置。

修改`SecurityConfig`中的`UserDetailsService`bean。

```java
@Autowired
private DataSource dataSource;
@Bean
public UserDetailsService userDetailsService() {
	return new JdbcUserDetailsManager(dataSource);
}
```

`Spring Authorization Server`有三张表，对应的bean也要修改三处

```java
@Autowired
JdbcTemplate jdbcTemplate;
@Bean
public RegisteredClientRepository registeredClientRepository() {

  return new JdbcRegisteredClientRepository(jdbcTemplate);
}

@Bean
public OAuth2AuthorizationService authorizationService() {
  return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository());
}

@Bean
public OAuth2AuthorizationConsentService authorizationConsentService() {
  return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository());
}
```

上述三个类对应`Spring Authorization Server`的三个表。



4. 初始化表数据

需要初始化三张表数据，分别是`users`,`authorities`, `oauth2_registered_client`

`users`,`authorities`需要通过`UserDetailsManager`类来实现，我暂时使用junit Test来实现。

```java
package com.itlab1024;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.function.Function;

@SpringBootTest
class ApplicationTests {

    /**
     * 初始化客户端信息
     */
    @Autowired
    private UserDetailsManager userDetailsManager;

    /**
     * 创建用户信息
     */
    @Test
    void testSaveUser() {
        UserDetails userDetails = User.builder()..passwordEncoder(s -> "{bcrypt}" + new BCryptPasswordEncoder().encode(s))
                .username("user")
                .password("password")
                .roles("ADMIN")
                .build();
        userDetailsManager.createUser(userDetails);
    }

}
```

执行完毕后两个表的记录如下：

users：

| username | password                                                     | enabled |
| :------- | :----------------------------------------------------------- | :------ |
| user     | $2a$10$IuZ1O.01lOQ.PykcSwKkRebij7XozYN3WCRBxss9gF36iyDnlsswG | 1       |

authories:

| username | authority   |
| :------- | :---------- |
| user     | ROLE\_ADMIN |

​		

创建client信息

```java
/**
     * 创建clientId信息
     */
    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Test
    @Test
    void testSaveClient() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("messaging-client")
                .clientSecret("{bcrypt}" + new BCryptPasswordEncoder().encode("secret"))
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc")
                .redirectUri("http://127.0.0.1:8080/authorized")
                .scope(OidcScopes.OPENID).scope("message.read")
                .scope("message.write")
                .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                .build();
        registeredClientRepository.save(registeredClient);
    }
```

创建完成后，`oauth2_registered_client`表中的记录如下：

| id                                   | client\_id       | client\_id\_issued\_at | client\_secret                                               | client\_secret\_expires\_at | client\_name                         | client\_authentication\_methods | authorization\_grant\_types                            | redirect\_uris                                               | scopes                            | client\_settings                                             | token\_settings                                              |
| :----------------------------------- | :--------------- | :--------------------- | :----------------------------------------------------------- | :-------------------------- | :----------------------------------- | :------------------------------ | :----------------------------------------------------- | :----------------------------------------------------------- | :-------------------------------- | :----------------------------------------------------------- | :----------------------------------------------------------- |
| f0ff36c2-1245-41a6-8c92-5ac5c049b268 | messaging-client | 2022-07-02 20:35:26    | {bcrypt}$2a$10$yttQ.mFAnOmw99L.cKb8EeHs/O9UXXL721nH2s/2oOoH2UwOfc32. | NULL                        | f0ff36c2-1245-41a6-8c92-5ac5c049b268 | client\_secret\_basic           | refresh\_token,client\_credentials,authorization\_code | http://127.0.0.1:8080/authorized,http://127.0.0.1:8080/login/oauth2/code/messaging-client-oidc | openid,message.read,message.write | {"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":false,"settings.client.require-authorization-consent":true} | {"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":\["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"\],"settings.token.access-token-time-to-live":\["java.time.Duration",300.000000000\],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.core.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":\["java.time.Duration",3600.000000000\]} |



5. 测试服务

​	授权码模式

访问：http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=messaging-client&scope=message.read&redirect_uri=http://127.0.0.1:8080/authorized

输入用户名密码（user, password）后，勾选scope，确认后，通过地址栏能或得code。

![获取code](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231153665.png)

获取到的code是

```tex
ZPO_JhUNM69j46JqZIGTTE_fvyzdZ30irinvQEW1DwFBQmWKhrwX-3GhR0a1l6uRoo4au9P1xl8Y6ig8SwDtXyTMLeSyHZC5PN8qwYwDkucQVqQLD7zNZLsdOIOwtLT5
```

获取token

![image-20220702204241459](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231153217.png)



结果是：

```json
{
    "access_token": "eyJraWQiOiJmZGZkN2YzMy1lOTVjLTQ5MDktYjM0Ny1jODMwMThhZDQ4NDQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1Njc2NTczNiwic2NvcGUiOlsibWVzc2FnZS5yZWFkIl0sImlzcyI6Imh0dHA6XC9cLzEyNy4wLjAuMTo4MDgwIiwiZXhwIjoxNjU2NzY2MDM2LCJpYXQiOjE2NTY3NjU3MzZ9.KOI5QfUYXNTmZz36abFFBcIoerbQssjJEPAwzBLB1jXeazT_lzu4EypPPniy9_34ZquBgAMBGaRGZyLwuJZ7dWeKLv9WZLtgtZQiGM4Ru8Z3_Ub8JYAdW8Sik0ZigSHjMIV1HlI50RzEN1ZNQ2OrmRf-XPAhfAnvC2y4VLNIIgtG-hMq1v6xjr70AZMQanRseapv8sM72rNaD71OWP6FxJb5mN8ZVv3DbNjMRUJ4YF5OTINx6igUB0nONEE1KJTmEYIFz4de7O3RuNhtuyaKFq1BId5pqE17uwxIp7X0cX5MD680l2wsoILqW_WlULHBVc2SHaI--Ku65tePP-cPPw",
    "refresh_token": "uWbL6c1QgwR-C5yORCY6qxR5-hN4qRZ91z6fsBtX0_6HkAeKaThattFt8tLwz91OsW7v5W2OwoDLnFwhjgfUCSKWxfyW2_OQMizlC0ytsgFRhYnwcy7j-2YB4EN0h9Es",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 299
}
```



刷新token

![image-20220702204341362](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231153292.png)

结果是：

```json
{
    "access_token": "eyJraWQiOiJmZGZkN2YzMy1lOTVjLTQ5MDktYjM0Ny1jODMwMThhZDQ4NDQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1Njc2NTgwOSwic2NvcGUiOlsibWVzc2FnZS5yZWFkIl0sImlzcyI6Imh0dHA6XC9cLzEyNy4wLjAuMTo4MDgwIiwiZXhwIjoxNjU2NzY2MTA5LCJpYXQiOjE2NTY3NjU4MDl9.MH59mGOwMC2l-yvKU8uSd_AyF8ej843rhWGFh8ne2AoEAK98-kcsYh2B3JGzFnL5YBsDCSWhIDA6j-XLsF2bCcb7KDkREfeAL8tkkSE1wYm8nevcDufPMgyrZQEwHFWYoBAqCHUB2zPCx8PmInKa0aGkZIN6KJbdSWfp_-tFchi8sn6ZwPJkr5gU9NvoddbIAKm9A-6AT_EGXnlupo1ME26PptrLmrISOvDlbpOToCYMvSm9r22AzU2AITaM-9rujql_9H-Lj7ML8gMak2VJCPfSGpPczlvBG6fnP3xcwW6xXBd6wpe-tI7Cu6Bz36Hh2KIJlGs07_MvAxoCPixJIg",
    "refresh_token": "uWbL6c1QgwR-C5yORCY6qxR5-hN4qRZ91z6fsBtX0_6HkAeKaThattFt8tLwz91OsW7v5W2OwoDLnFwhjgfUCSKWxfyW2_OQMizlC0ytsgFRhYnwcy7j-2YB4EN0h9Es",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 299
}
```



客户端模式：

获取token

![image-20220702204502682](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231153242.png)

结果是：

```json
{
    "access_token": "eyJraWQiOiJmZGZkN2YzMy1lOTVjLTQ5MDktYjM0Ny1jODMwMThhZDQ4NDQiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJtZXNzYWdpbmctY2xpZW50IiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsIm5iZiI6MTY1Njc2NTg4Miwic2NvcGUiOlsib3BlbmlkIiwibWVzc2FnZS5yZWFkIiwibWVzc2FnZS53cml0ZSJdLCJpc3MiOiJodHRwOlwvXC8xMjcuMC4wLjE6ODA4MCIsImV4cCI6MTY1Njc2NjE4MiwiaWF0IjoxNjU2NzY1ODgyfQ.hgs-y0Pk69RT4cvnxsHZ2plhOQ8_IZM_4YbZL_1Rarpi5uBb6CbqUzqbUyAy-NXhFRqJfUkcVvXEQ8MWcvY6bPILg_Aqi4T5ZlFij0OACmqE3QmEenEkAJ8cxBA_fl9-k_Wcv8faepP5dlX8apPTX5i_6DW5p8IxtM1-tonhWNEEHjVVVpaktTd0yLYlhe_bbcVHpNAHpYXSO9sl18EamAJC5j9-rgN02w3XMPMd7oLxfR6IN74jOynSK4dZUmT6NnKqq9_V0DWGJWXHCjddiVN85VS5mojoz_74DaFT480fuy9XmhoYhv1xFqPxpqSUQrlCwKzAktbCvka8b9vPXQ",
    "scope": "openid message.read message.write",
    "token_type": "Bearer",
    "expires_in": 299
}
```

> 推送分支v3.0.0



## 自定义jwt字段

将上面的jwt解码后结果如下：

![image-20220702210738367](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231153032.png)

接下来我们增加一个自定义header和claim.

需要使用`OAuth2TokenCustomizer`来实现。

```java
@Bean
public JwtEncoder jwtEncoder() {
  return new NimbusJwtEncoder(jwkSource());
}

@Bean
public OAuth2TokenGenerator<?> tokenGenerator() {
  JwtGenerator jwtGenerator = new JwtGenerator(jwtEncoder());
  jwtGenerator.setJwtCustomizer(jwtCustomizer());
  OAuth2AccessTokenGenerator accessTokenGenerator = new OAuth2AccessTokenGenerator();
  OAuth2RefreshTokenGenerator refreshTokenGenerator = new OAuth2RefreshTokenGenerator();
  return new DelegatingOAuth2TokenGenerator(
    jwtGenerator, accessTokenGenerator, refreshTokenGenerator);
}

@Bean
public OAuth2TokenCustomizer<JwtEncodingContext> jwtCustomizer() {
  return context -> {
    JwsHeader.Builder headers = context.getHeaders();
    JwtClaimsSet.Builder claims = context.getClaims();
    if (context.getTokenType().equals(OAuth2TokenType.ACCESS_TOKEN)) {
      // Customize headers/claims for access_token
      headers.header("customerHeader", "这是一个自定义header");
			claims.claim("customerClaim", "这是一个自定义Claim");
    } else if (context.getTokenType().getValue().equals(OidcParameterNames.ID_TOKEN)) {
      // Customize headers/claims for id_token
      
    }
  };
}
```

重启应用，我通过客户端模式获取token，并解码查看。

![image-20220702212018505](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231153546.png)





# OpenID Connect 1.0协议

`Spring Authorization Server`支持OAuth2.1协议，同时也支持`OpenID Connect 1.0`协议，该协议是`OAuth2`协议的上层协议，这里我就不解释了，可自行百度。

默认是不支持该协议的，需要我们进行配置。

## 用户端点

需要修改authorizationServerSecurityFilterChain为如下内容：

```
authorizationServerConfigurer
    .oidc(oidc -> {
      oidc.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.userInfoMapper(oidcUserInfoAuthenticationContext -> {
        OAuth2AccessToken accessToken = oidcUserInfoAuthenticationContext.getAccessToken();
        Map<String, Object> claims  = new HashMap<>();
        claims.put("url", "https://github.com/ITLab1024");
        claims.put("accessToken", accessToken);
        claims.put("sub", oidcUserInfoAuthenticationContext.getAuthorization().getPrincipalName());
        return new OidcUserInfo(claims);
      }));
    }
         );
  http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);


@Bean
public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
	return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
}
```



请注意：我的client(messaging-client)设置的时候scope设置了openid的支持。

测试：

授权码模式获取token：

http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=messaging-client&scope=openid&redirect_uri=http://127.0.0.1:8080/authorized

请再次注意，这里的scope必须包含openid。

输入用户名密码确认后，获得的code如下：

```tex
nngt651MwKjuKPK0NJfxOU6KHE6okJ8RK3P7fdyJuc2o_GXdaDTrQGnBYjabcH9Bj9sZR6mxlZuojhldB349NZgKBfl8P67BWuX5jmCzXBc-a48pv-rPAyP7kBVvc031
```

获取token，得到的token是：

```json
{
    "access_token": "eyJjdXN0b21lckhlYWRlciI6Iui_meaYr-S4gOS4quiHquWumuS5iWhlYWRlciIsImFsZyI6IlJTMjU2Iiwia2lkIjoiMDM0OTEyMjYtZDIxYi00ZDBhLWFjMTktMTk0M2ViOTE5NzYzIn0.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsImN1c3RvbWVyQ2xhaW0iOiLov5nmmK_kuIDkuKroh6rlrprkuYlDbGFpbSIsIm5iZiI6MTY1Njc2OTMzNiwic2NvcGUiOlsib3BlbmlkIl0sImlzcyI6Imh0dHA6XC9cLzEyNy4wLjAuMTo4MDgwIiwiZXhwIjoxNjU2NzY5NjM2LCJpYXQiOjE2NTY3NjkzMzZ9.Xckgu8cS1SMhP1lJElqCjI1bLy2TvfvTCUjvlWjxxwU17jpDkVY6yIcFUFyGLsGFxd-1CIVE7hyojwxOT4d7QASUr33LdlWY8rlJ4vDm9VzQwQstB1K1bCgWg5ZcKpWdDXBrcA2ZL14tNvpDH9qsTfFpuIM1pGc-YWFL5k3CuPU0Us_U-P6gQqxpdJsBebctCXyPncmXA7zVp60kGPtenR0E9mjBx7DMZ30L00Hm9bZgHiy5G4QI87KRuJh9tR187ZK08IW3-0UEU-pzDhWE1YJaC0k4lQSC1ZplJq2q0Cmi2E_p2ZtxK4uduNol2-TZtiNs33O83XrAN1X5hke-ew",
    "refresh_token": "RFxOTgEWcN__IbJC2D0I1qS0lq7rEDr7OTQApwZRq6edAQubjeGXTRn0_2VKnP2lYdSLiGKn4IzrrcPpJ7mFFEgppTQJpnGSX2kE_9tJ9D8ImFE8mOEc5HLkW0G6TXBR",
    "scope": "openid",
    "id_token": "eyJraWQiOiIwMzQ5MTIyNi1kMjFiLTRkMGEtYWMxOS0xOTQzZWI5MTk3NjMiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsImF6cCI6Im1lc3NhZ2luZy1jbGllbnQiLCJpc3MiOiJodHRwOlwvXC8xMjcuMC4wLjE6ODA4MCIsImV4cCI6MTY1Njc3MTEzNiwiaWF0IjoxNjU2NzY5MzM2fQ.ETYbleyPtP6v8dr8Mz0RBFxwFGIMRmNTX8vvPt18MWDyKiioYzn1OMFaDmEY5NESTwI47PFeKvUevmeeTCNRncQKWe_FBbgB8ZilI4Q944zLIUUUQmZHlANNfQ8EhBdbnJ2b3iblvhxSOGNCV_nSc2Rg0oikjpxbalWQjfuJHDsqKFny4ReU-ziZLc7Q5PVu3xuNfQN_iZOZq2c7pu6e5sP0p3YoD_YrjimAk0Ich0wrqiR_a9N5lT-EDh0iGWUc6US-FljEWxm-W1sUwS3E5xxSZxY2AJcmSXBIckwxVeWzG0VP9JoSEPrrs6tErzUwEJzkiw-zxYDPJvMb9sO8fw",
    "token_type": "Bearer",
    "expires_in": 299
}
```

通过token，获取OIDC的用户端点：

![image-20220702214350843](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231153021.png)

这里的sub就是用户的标志，当然也可以增加很多自定义信息。

修改如下：

```java
@Bean
@Order(Ordered.HIGHEST_PRECEDENCE)
public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
  OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
    new OAuth2AuthorizationServerConfigurer<>();
  RequestMatcher endpointsMatcher = authorizationServerConfigurer
    .getEndpointsMatcher();

  http
    .requestMatcher(endpointsMatcher)
    .authorizeRequests(authorizeRequests ->
                       authorizeRequests.anyRequest().authenticated()
                      )
    .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
    .apply(authorizationServerConfigurer);
  http
    // Redirect to the login page when not authenticated from the
    // authorization endpoint
    .exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
  // 也可以使用如下代码，跳转到login page
  //        http.formLogin(Customizer.withDefaults());

  authorizationServerConfigurer
    .oidc(oidc -> {
      oidc.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.userInfoMapper(oidcUserInfoAuthenticationContext -> {
        OAuth2AccessToken accessToken = oidcUserInfoAuthenticationContext.getAccessToken();
        Map<String, Object> claims  = new HashMap<>();
        claims.put("url", "https://github.com/ITLab1024");
        claims.put("accessToken", accessToken);
        claims.put("sub", oidcUserInfoAuthenticationContext.getAuthorization().getPrincipalName());
        return new OidcUserInfo(claims);

      }));
    }
         );
  http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);


  return http.build();
}
```

重新获取用户信息，得到如下内容：

```json
{
    "accessToken": {
        "tokenValue": "eyJjdXN0b21lckhlYWRlciI6Iui_meaYr-S4gOS4quiHquWumuS5iWhlYWRlciIsImFsZyI6IlJTMjU2Iiwia2lkIjoiYTgxYmRkZWItZGZlMC00ZjZmLTk1NmMtOWMwNzMwZTc0Y2E0In0.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsImN1c3RvbWVyQ2xhaW0iOiLov5nmmK_kuIDkuKroh6rlrprkuYlDbGFpbSIsIm5iZiI6MTY1Njc3MDkxMSwic2NvcGUiOlsib3BlbmlkIl0sImlzcyI6Imh0dHA6XC9cLzEyNy4wLjAuMTo4MDgwIiwiZXhwIjoxNjU2NzcxMjExLCJpYXQiOjE2NTY3NzA5MTF9.csnOK5JNzZK1-LflchrGsrm-Czfg0jtLizRtP8cHw88u9yXDhfUBzShQ58bNygvjpEakmd_byUlLkNC9sfGhae7t5U9fGgu6YzWhq3EKn-4g8TCJLMg6G8kmzCuqgLx6t_AaDDwhUQ7lsrVu99lahvE57mP80RmRGTBCnMbxfKbzvdj0nsMW0awYANd0R9m__gYL-O5WWAc7-qrcylPMzIKTOqT-cX2-pKzlAuhpcxsupQSNdnCEoH_VeoICMqcJnsz2l8mQjmHOnQ9YAddCvnLGeXcqyW24KhnUcJ0LwZLYrrvGdZ323lQKZSytTXfc4d9O1OzGkwR9OYmKif8Xbg",
        "issuedAt": 1656770912.000000000,
        "expiresAt": 1656771212.000000000,
        "tokenType": {
            "value": "Bearer"
        },
        "scopes": [
            "openid"
        ]
    },
    "url": "https://github.com/ITLab1024"
  	"sub": "user"
}
```

实际开发中，我们可以自定义，昵称、性别，头像等非敏感信息。

## 查看OpenID的配置

![image-20220703213056662](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231154896.png)

结果是：

```json
{
    "issuer": "http://localhost:8080",
    "authorization_endpoint": "http://localhost:8080/oauth2/authorize",
    "token_endpoint": "http://localhost:8080/oauth2/token",
    "token_endpoint_auth_methods_supported": [
        "client_secret_basic",
        "client_secret_post",
        "client_secret_jwt",
        "private_key_jwt"
    ],
    "jwks_uri": "http://localhost:8080/oauth2/jwks",
    "userinfo_endpoint": "http://localhost:8080/userinfo",
    "response_types_supported": [
        "code"
    ],
    "grant_types_supported": [
        "authorization_code",
        "client_credentials",
        "refresh_token"
    ],
    "subject_types_supported": [
        "public"
    ],
    "id_token_signing_alg_values_supported": [
        "RS256"
    ],
    "scopes_supported": [
        "openid"
    ]
}
```

## 客户端注册端点

OpenID Connect 1.0客户端注册端点默认禁用，因为许多部署不需要动态客户端注册。

增加如下配置：

```java
@Bean
@Order(Ordered.HIGHEST_PRECEDENCE)
public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
  OAuth2AuthorizationServerConfigurer<HttpSecurity> authorizationServerConfigurer =
    new OAuth2AuthorizationServerConfigurer<>();
  RequestMatcher endpointsMatcher = authorizationServerConfigurer
    .getEndpointsMatcher();
  http
    .requestMatcher(endpointsMatcher)
    .authorizeRequests(authorizeRequests ->
                       authorizeRequests.anyRequest().authenticated()
                      )
    .csrf(csrf -> csrf.ignoringRequestMatchers(endpointsMatcher))
    .apply(authorizationServerConfigurer);
  http
    // Redirect to the login page when not authenticated from the
    // authorization endpoint
    .exceptionHandling((exceptions) -> exceptions.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
  // 也可以使用如下代码，跳转到login page
  //        http.formLogin(Customizer.withDefaults());

  authorizationServerConfigurer
    .oidc(oidc -> {
      // 用户信息
      oidc.userInfoEndpoint(userInfoEndpoint -> userInfoEndpoint.userInfoMapper(oidcUserInfoAuthenticationContext -> {
        OAuth2AccessToken accessToken = oidcUserInfoAuthenticationContext.getAccessToken();
        Map<String, Object> claims = new HashMap<>();
        claims.put("url", "https://github.com/ITLab1024");
        claims.put("accessToken", accessToken);
        claims.put("sub", oidcUserInfoAuthenticationContext.getAuthorization().getPrincipalName());
        return new OidcUserInfo(claims);

      }));
      // 客户端注册
      oidc.clientRegistrationEndpoint(Customizer.withDefaults());
    }
         );
  http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);


  return http.build();
}
```

请注意：

![image-20220703213506592](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231154932.png)

测试：

请求：http://127.0.0.1:8080/oauth2/authorize?response_type=code&client_id=messaging-client&scope=client.create&redirect_uri=http://127.0.0.1:8080/authorized

输入用户名密码后：

![image-20220703214606816](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231154254.png)

勾选scope，并提交，从地址栏中获取到code。

```tex
qdd5jgQxyfAlZELZr8kclamAaqkXlWxoEPa5h_7E0BbNLDkgfjDLnpo5SmPrFbZxZJVwO3KCMpmQD5D_y-2e_in8UD50ZpDPNs5GXjvOs_vU-tjhf0V-A7C9H1Phf9gw
```

获取accessToken

![image-20220703214720168](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231154238.png)

json结果是：

```java
{
    "access_token": "eyJjdXN0b21lckhlYWRlciI6Iui_meaYr-S4gOS4quiHquWumuS5iWhlYWRlciIsImFsZyI6IlJTMjU2Iiwia2lkIjoiOWI1ZDkyZDAtZTY3ZC00ZDVjLTkyZmUtN2M2NDM3Y2Y4OGI4In0.eyJzdWIiOiJ1c2VyIiwiYXVkIjoibWVzc2FnaW5nLWNsaWVudCIsImN1c3RvbWVyQ2xhaW0iOiLov5nmmK_kuIDkuKroh6rlrprkuYlDbGFpbSIsIm5iZiI6MTY1Njg1NjAyMCwic2NvcGUiOlsiY2xpZW50LmNyZWF0ZSJdLCJpc3MiOiJodHRwOlwvXC8xMjcuMC4wLjE6ODA4MCIsImV4cCI6MTY1Njg1NjMyMCwiaWF0IjoxNjU2ODU2MDIwfQ.ODhSpJ73yrkHvKbcFDbjKozV2q1vGqim1kgKXLxgc402phmS0JvhvviXqbc_udeDSZEdozy9iNCoEENcLWRsBh_RPRiQ6gx-IVXZouTnQkvl_nJChSDRv6a75HqDnxW3Q_iFQlxJx9wbXUIJ1k4mt2q0VqfPS5tTKoblhuEdAKyL90RLAEP1BSzxFFEYeSKIl-nEwsUWsZY9mqnzw33Z1dRVgZLrhIdhpwg41sSFKqw6B5yRzOHrc_0_nAW10TJK9ONbxrJvTc2ZHI8yLBjRoqEdFPgcOMkBHAH8baGsoHNLGEbVK4U8fb_hvZ1F9Ara3Aw3_yga4kJciGi_yt6y-A",
    "refresh_token": "Hux9d04U-mi1GIFhy3t244xpS9wvrDaPSYXoR0gRP6vlQuKqAWlEER8RbdP7EAGOuFGoAyZ-nKAoxBL5JZxuwIyoGECrgHTEnof5eDaMVdrbNzwr8B8xxSZ0f-JicBys",
    "scope": "client.create",
    "token_type": "Bearer",
    "expires_in": 299
}
```



通过获取的accessToken，POST请求`/connect/register`接口

![请求参数](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202207231154184.png)

返回结果：

```json
{
    "client_id": "Gw-kfSnh0R948WSJnAdIQCbXtcfifFhDygB7vPOWieI",
    "client_id_issued_at": 1656856140,
    "client_name": "My Example",
    "client_secret": "lmngmSlQNBJdCpBO4Ha2gubD0jtK_3Px2khf-u_tpyFZAT6imLV5F_bcsyZCZXPd",
    "redirect_uris": [
        "https://client.example.org/callback",
        "https://client.example.org/callback2"
    ],
    "grant_types": [
        "authorization_code"
    ],
    "response_types": [
        "code"
    ],
    "token_endpoint_auth_method": "client_secret_basic",
    "id_token_signed_response_alg": "RS256",
    "registration_client_uri": "http://127.0.0.1:8080/connect/register?client_id=Gw-kfSnh0R948WSJnAdIQCbXtcfifFhDygB7vPOWieI",
    "registration_access_token": "eyJjdXN0b21lckhlYWRlciI6Iui_meaYr-S4gOS4quiHquWumuS5iWhlYWRlciIsImFsZyI6IlJTMjU2Iiwia2lkIjoiOWI1ZDkyZDAtZTY3ZC00ZDVjLTkyZmUtN2M2NDM3Y2Y4OGI4In0.eyJzdWIiOiJHdy1rZlNuaDBSOTQ4V1NKbkFkSVFDYlh0Y2ZpZkZoRHlnQjd2UE9XaWVJIiwiYXVkIjoiR3cta2ZTbmgwUjk0OFdTSm5BZElRQ2JYdGNmaWZGaER5Z0I3dlBPV2llSSIsImN1c3RvbWVyQ2xhaW0iOiLov5nmmK_kuIDkuKroh6rlrprkuYlDbGFpbSIsIm5iZiI6MTY1Njg1NjE0MCwic2NvcGUiOlsiY2xpZW50LnJlYWQiXSwiaXNzIjoiaHR0cDpcL1wvMTI3LjAuMC4xOjgwODAiLCJleHAiOjE2NTY4NTY0NDAsImlhdCI6MTY1Njg1NjE0MH0.iUPvyaCfpumCMesa-5JKsYdA9w-p6BZvh-7Fsn6vaysJKzCOHdr5QrFsvudnmyJYtv1rmrC8lbljycMXGcGRgBUSL1Zi5AFSoGCflYnVLvgHEQE70WLlcTFf4SW3JTQTBd2iTpTxAnNOQLG8UYgfDj4KQRAqkmdUUxNc-mPdpUNJQcDciNUgvuW5YhED3aPEVEp4tNfF47umyMUJ5kSGdFNOc3JDVI_nFE3TajxP1WYzvbF5SY8rq7TEtQPz1SB-YwSKZwusABjRQrmQAn0-oI-c-MvxjbyzMQPG6XXDArVv9rSfuouShU6VZYnPhL4t_D11RLPvL62AiLNya1VzIQ",
    "client_secret_expires_at": 0
}
```

查看数据库表（oauth2_registered_client），可以看到多了一条记录

| id                                   | client\_id                                  | client\_id\_issued\_at | client\_secret                                               | client\_secret\_expires\_at | client\_name | client\_authentication\_methods | authorization\_grant\_types | redirect\_uris                                               | scopes | client\_settings                                             | token\_settings                                              |
| :----------------------------------- | :------------------------------------------ | :--------------------- | :----------------------------------------------------------- | :-------------------------- | :----------- | :------------------------------ | :-------------------------- | :----------------------------------------------------------- | :----- | :----------------------------------------------------------- | :----------------------------------------------------------- |
| f60a7102-08f6-4217-99c8-6d73a5dba9ef | Gw-kfSnh0R948WSJnAdIQCbXtcfifFhDygB7vPOWieI | 2022-07-03 21:49:01    | lmngmSlQNBJdCpBO4Ha2gubD0jtK\_3Px2khf-u\_tpyFZAT6imLV5F\_bcsyZCZXPd | NULL                        | My Example   | client\_secret\_basic           | authorization\_code         | https://client.example.org/callback,https://client.example.org/callback2 |        | {"@class":"java.util.Collections$UnmodifiableMap","settings.client.require-proof-key":true,"settings.client.require-authorization-consent":true} | {"@class":"java.util.Collections$UnmodifiableMap","settings.token.reuse-refresh-tokens":true,"settings.token.id-token-signature-algorithm":\["org.springframework.security.oauth2.jose.jws.SignatureAlgorithm","RS256"\],"settings.token.access-token-time-to-live":\["java.time.Duration",300.000000000\],"settings.token.access-token-format":{"@class":"org.springframework.security.oauth2.core.OAuth2TokenFormat","value":"self-contained"},"settings.token.refresh-token-time-to-live":\["java.time.Duration",3600.000000000\]} |

说明客户端已经注册成功。

---

> Spring Authorization Server其实目前也在不断完善中，很多功能也是不全的。
>
> 如果有人对openid connect1.0协议不了解，建议查看https://openid.net/connect/。
>
> 本文Github地址：https://github.com/itlab1024/Spring-Security-OAuth2-Tutorial/tree/main/oauth2-server

---

> 理解有限，很多功能未能完全展现，会持续不断的进行更新，期待您的关注。
