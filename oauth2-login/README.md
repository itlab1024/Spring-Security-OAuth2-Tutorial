> Spring Security OAuth2 Login基本使用， 本文主要介绍下使用Github和自定义授权服务器登录功能。

![image-20220805151832899](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208051518254.png)

# 创建项目

笔者使用IDEA工具。

## Maven依赖

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
    <parent>
        <artifactId>spring-security-tutorial</artifactId>
        <groupId>com.itlab1024</groupId>
        <version>0.0.1-SNAPSHOT</version>
    </parent>
    <modelVersion>4.0.0</modelVersion>

    <artifactId>oauth2-login</artifactId>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-oauth2-client</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-thymeleaf</artifactId>
        </dependency>
    </dependencies>

</project>
```



## 项目配置

application.yaml配置，请注意图中github的client_id和client_secret，需要自己去github设置。然后拷贝到配置文件中，如果创建请款下面的申请 Github OAuth App

```yaml
server:
  port: 8000
spring:
  security:
    oauth2:
      client:
        registration:
          github:
            client-id: <github的clientID，去https://github.com/settings/developers的OAuth Apps中创建一个>
            client-secret: <github的clientSecret>
          itlab1024:
            client-id: itlab1024
            client-secret: itlab1024
            authorization-grant-type: authorization_code
            client-authentication-method: client_secret_basic
            scope: openid,message.read,message.write
            redirect-uri: http://oauth2login:8000/login/oauth2/code/itlab1024
            provider: itlab1024
            client-name: IT实验室
        provider:
          itlab1024:
#            authorization-uri: http://oauth2server:8080/oauth2/authorize
#            token-uri: http://oauth2server:8080/oauth2/token
#            jwk-set-uri: http://oauth2server:8080/oauth2/jwks
#            user-info-uri: http://oauth2server:8080/userinfo
#            user-name-attribute: sub
            #单独配置如下一个也是可以的，底层会自动寻址，如果自定义过url，需要使用上面方式配置(修改oauthserve里上面那些url后，使用如下配置能否有效未测试)
            issuer-uri: http://oauth2server:8080
```

## 申请 Github OAuth App

打开[github官网](https://github.com)，登录后，进入设置(setting)。

![image-20220805133016829](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208051330092.png)

点击按钮开始创建OAuth App

![image-20220805133341271](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208051333370.png)

创建完毕后，将client_id和client_secret设置到application.yaml文件中。

# 创建接口

创建默认的项目请求，使用页面展示登录成功后用户和授权信息。

```java
package com.itlab1024.oauth2login.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Slf4j
public class IndexController {

    /**
     登录成功后才能访问到用户信息和授权信息等
     *
     * @param model
     * @param authorizedClient
     * @param oauth2User
     * @return
     */
    @GetMapping("/")
    public String index(Model model, @RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient,
                        @AuthenticationPrincipal OAuth2User oauth2User) {
        System.out.println(authorizedClient.getAccessToken());
        model.addAttribute("authorizedClient", authorizedClient);
        model.addAttribute("oauth2User", oauth2User);
        return "meta";
    }

}

```



meta.html

```html
<!DOCTYPE html>
<html lang="en" xmlns:th="http://www.thymeleaf.org" xmlns="http://www.w3.org/1999/html">
<head>
    <meta charset="UTF-8">
    <title>登录成功</title>
</head>
<body>
您已经通过客户端<span style="" th:text="${authorizedClient.clientRegistration.clientId}"></span>登录成功!<br>
用户信息：<span th:text="${oauth2User.attributes}"></span><br>
授权信息是：<br>
类型: <span th:text="${authorizedClient.accessToken.tokenType}"></span><br>
token: <span th:text="${authorizedClient.accessToken.tokenValue}"></span><br>
范围: <span th:text="${authorizedClient.accessToken.scopes}"></span><br>
过期时间: <span th:text="${authorizedClient.accessToken.expiresAt}"></span><br>
签发时间: <span th:text="${authorizedClient.accessToken.issuedAt}"></span><br>
</body>
</html>
```



# 测试

## 说明

先启动oauth2-server项目，再启动oauth2-login项目，这里要修改hosts文件。

```tex
127.0.0.1 oauth2server
127.0.0.1 oauth2login
```

使用我的demo是必须修改的，但是你如果自己搭建，也可以不修改，不过oauth2对于回调redirect_uri，如果是本地回环地址是不允许的。为了不必要的坑，不如直接修改hosts方便。

请求oauth2-login项目地址:http://oauth2login:8000

![image-20220805134251800](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208051342915.png)

可以看到上图中有两种登录方式，一种是使用github登录，一种是使用我自己搭建的OAuth2 Server登录。

一个一个来测试下。

## Github登录测试

![image-20220805134445254](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208051344356.png)

输出用户名密码后

![image-20220805134510149](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208051345322.png)

等待跳转后，会跳转到项目默认主页。

![image-20220805134615377](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208051346472.png)

## IT实验室登录（自定义授权服务器）

![image-20220805134705855](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208051347990.png)

输入用户名（user）密码（password）

![image-20220805135011406](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208051350572.png)

支持OAuth2 Login功能就完成了，接下来我简单说下一些其他配置，以及注意项。

# 附录

上面的例子就是一个基本的OAuth2Login登录。

我似乎也没做什么，无非就引入了依赖，在application.yaml中增加了点客户端配置。

也确实如此，这得益于框架为我们做了很多东西，很多东西是框架默认配置的，这个配置类叫做

OAuth2ClientAutoConfiguration

源码如下：

```java
/*
 * Copyright 2012-2022 the original author or authors.
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

package org.springframework.boot.autoconfigure.security.oauth2.client.servlet;

import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.autoconfigure.security.servlet.SecurityAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;

/**
 * {@link EnableAutoConfiguration Auto-configuration} for OAuth client support.
 *
 * @author Madhura Bhave
 * @author Phillip Webb
 * @since 2.0.0
 */
@AutoConfiguration(before = SecurityAutoConfiguration.class)
@ConditionalOnClass({ EnableWebSecurity.class, ClientRegistration.class })
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@Import({ OAuth2ClientRegistrationRepositoryConfiguration.class, OAuth2WebSecurityConfiguration.class })
public class OAuth2ClientAutoConfiguration {

}
```

这个类有导入了两个类OAuth2ClientRegistrationRepositoryConfiguration类和OAuth2WebSecurityConfiguration。

源码如下：

```java
/*
 * Copyright 2012-2019 the original author or authors.
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

package org.springframework.boot.autoconfigure.security.oauth2.client.servlet;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.oauth2.client.ClientsConfiguredCondition;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesRegistrationAdapter;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Conditional;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;

/**
 * {@link Configuration @Configuration} used to map {@link OAuth2ClientProperties} to
 * client registrations.
 *
 * @author Madhura Bhave
 */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(OAuth2ClientProperties.class)
@Conditional(ClientsConfiguredCondition.class)
class OAuth2ClientRegistrationRepositoryConfiguration {

	@Bean
	@ConditionalOnMissingBean(ClientRegistrationRepository.class)
	InMemoryClientRegistrationRepository clientRegistrationRepository(OAuth2ClientProperties properties) {
		List<ClientRegistration> registrations = new ArrayList<>(
				OAuth2ClientPropertiesRegistrationAdapter.getClientRegistrations(properties).values());
		return new InMemoryClientRegistrationRepository(registrations);
	}

}
```

另一个类的源码如下

```java
/*
 * Copyright 2012-2022 the original author or authors.
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

package org.springframework.boot.autoconfigure.security.oauth2.client.servlet;

import org.springframework.boot.autoconfigure.condition.ConditionalOnBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.security.ConditionalOnDefaultWebSecurity;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.web.SecurityFilterChain;

/**
 * {@link SecurityFilterChain} to add OAuth client support.
 *
 * @author Madhura Bhave
 * @author Phillip Webb
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnBean(ClientRegistrationRepository.class)
class OAuth2WebSecurityConfiguration {

	@Bean
	@ConditionalOnMissingBean
	OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
		return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
	}

	@Bean
	@ConditionalOnMissingBean
	OAuth2AuthorizedClientRepository authorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
		return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
	}

	@Configuration(proxyBeanMethods = false)
	@ConditionalOnDefaultWebSecurity
	static class OAuth2SecurityFilterChainConfiguration {

		@Bean
		SecurityFilterChain oauth2SecurityFilterChain(HttpSecurity http) throws Exception {
			http.authorizeRequests((requests) -> requests.anyRequest().authenticated());
			http.oauth2Login(Customizer.withDefaults());
			http.oauth2Client();
			return http.build();
		}

	}
}
```

而我们如果想自定义，或者完全覆盖他的配置，就需要使用类似如下代码

```java
@Configuration
public class OAuth2LoginConfig {

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorize -> authorize
				.anyRequest().authenticated()
			)
			.oauth2Login(withDefaults());
		return http.build();
	}

	@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		return new InMemoryClientRegistrationRepository(this.googleClientRegistration());
	}

	private ClientRegistration googleClientRegistration() {
		return ClientRegistration.withRegistrationId("google")
			.clientId("google-client-id")
			.clientSecret("google-client-secret")
			.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
			.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
			.redirectUri("{baseUrl}/login/oauth2/code/{registrationId}")
			.scope("openid", "profile", "email", "address", "phone")
			.authorizationUri("https://accounts.google.com/o/oauth2/v2/auth")
			.tokenUri("https://www.googleapis.com/oauth2/v4/token")
			.userInfoUri("https://www.googleapis.com/oauth2/v3/userinfo")
			.userNameAttributeName(IdTokenClaimNames.SUB)
			.jwkSetUri("https://www.googleapis.com/oauth2/v3/certs")
			.clientName("Google")
			.build();
	}
}
```
