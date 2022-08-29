>OAuth2 资源服务器

# 支持类型

Spring Security 支持两种OAuth2的保护端点，一种是Jwt，一种是Opaque Tokens，资源服务器可以设置使用哪种类型（可以去我的博客去看）。

# JWT

我的资源服务器目前实现了JWT的类型，所以我接下来尝试创建JWT方式的资源服务器。

# 项目

## 引入依赖

pom.xml

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

    <artifactId>oauth2-resource</artifactId>

    <properties>
        <maven.compiler.source>17</maven.compiler.source>
        <maven.compiler.target>17</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-resource-server</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.security</groupId>
            <artifactId>spring-security-oauth2-jose</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
    </dependencies>

</project>
```

## 配置

application.yaml

```yaml
server:
  port: 8001
spring:
  security:
    oauth2:
      resourceserver:
        jwt:
          issuer-uri: http://oauth2server:8080
```

## 创建受保护的资源

```java
package com.itlab1024.oauth2resource.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * 资源控制器
 */
@RestController
public class ResController {
    /**
     * 受保护的资源
     * @return
     */
    @GetMapping("res")
    public String getRes() {
        return "成功获取到受保护的资源";
    }

    /**
     * 通过注解控制权限
     * @return
     */
    @GetMapping("res2")
    @PreAuthorize("hasRole('ADMIN')")
    public String getRes2() {
        return "成功获取到受保护的资源";
    }
}

```

# 测试

如果不提供token，则返回如下结果

![image-20220809133530137](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208091335858.png)

获取授权码

```curl
http://oauth2server:8080/oauth2/authorize?response_type=code&client_id=itlab1024&scope=message.read&redirect_uri=http://oauth2login:8000/login/oauth2/code/itlab1024
```

得到如下code

```tex
S_wfZfXvyUDBAqMSqD76Fux-0AiIxHMN-3deR8CS7lIClpqVhNg9aoHI2iFxKYj2zShKNmzMUB1Bnhspwqj8Ek_7mBIjmdo-cXRr83tFeOu0IDLMxWADy10bZL4JULNM
```

通过code获取token

![image-20220809143034630](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208091430771.png)

```json
{
    "access_token": "eyJjdXN0b21lckhlYWRlciI6Iui_meaYr-S4gOS4quiHquWumuS5iWhlYWRlciIsImFsZyI6IlJTMjU2Iiwia2lkIjoiNjY5MGFkMTMtOTM4NC00NzdlLTlkZTctNmY2YTE2MzJhMWM4In0.eyJzdWIiOiJ1c2VyIiwiYXVkIjoiaXRsYWIxMDI0IiwiY3VzdG9tZXJDbGFpbSI6Iui_meaYr-S4gOS4quiHquWumuS5iUNsYWltIiwibmJmIjoxNjYwMDI2NTk0LCJzY29wZSI6WyJtZXNzYWdlLnJlYWQiXSwiaXNzIjoiaHR0cDpcL1wvb2F1dGgyc2VydmVyOjgwODAiLCJleHAiOjE2NjAwMjY4OTQsImlhdCI6MTY2MDAyNjU5NH0.Pmq6guRFYKhSITr4CHMxoo1XAigN25HHnSP2zn7_x9156ioHZnr4Y7uMu7nlC0cmQ_nun92I_2p3JG78H6p5iV4xJmzPepMHZclpmQRGQtsj6CPpLHZpyX6p8WixyAnDIMoypAiZ2xDLBRyyJx6UVgDzVStHgCB5Jd-mcFujc13IisPmuRoOI5LIE1J4V-UFHbCFLKLhO2_Ta8f_wwuYqPNi33Ml6g8AEehRY6ry8lF1NfaDjTIHeQua2qIEtOpxO3ZENueUyDbtwT_3ji-UmQ9r7NzzxNI3oIYTdJwQkeFVjb1WvliHeKpKZ2LQ0bnOHzBn54XTI1K34qg49zwuNQ",
    "refresh_token": "Twd1DSuuGNx-5s8UrtTO5yY9WJMNif7DJLkTtl2yuzESBJPaTWXPFeDVHF1UFMeCWcED1HWdWKcs42gPlSrnQS7FdK5S6p1dAdTsjdGPL36iClFPEH2ZODV4Cn295jJU",
    "scope": "message.read",
    "token_type": "Bearer",
    "expires_in": 299
}
```

通过获取到的token获取请求资源接口

![image-20220809143128548](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208091431885.png)

请求基于注解权限的接口

![image-20220809141942377](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208091419456.png)

**提示无权限!!!**

这就不对了，oauth2server中我注册的client(itlab1024)，是设置了角色ADMIN的，但是为什么提示我还是无权限呢？

没办法，Debug看下，看到如下内容：

![image-20220809143604039](https://itlab1024-1256529903.cos.ap-beijing.myqcloud.com/202208091436189.png)



scope在AuthoritySet中，但是我设置的角色确不在，查了些资料发现新版的确实是这样做的，至于为什么我还不知道，这跟以前的OAuth2 服务还是不同的。



我决定两种途径去查查，一个是通过github仓库issue看看是否有人提出这样的问题，官网人员如何回答的。二是看看新版OAuth2.1的文档是否有说明。



这个问题QQ群里之前有人提出来！！！



先写到这里，之后有了答案再补充，欢迎留言。

# 用户角色无法获取的问题
spring security5 默认的令牌校验逻辑只处理scope，而忽略了用户的授权信息。我又仔细看了下官方文档，没有相关设置。
但是对于Opaque模式的token可以使用自定义的方式来实现。JWT的方式目前我还没尝试如何解决。
> Opaque 不透明Token的定义方式，我并没有提交代码，可以进行查看官网文档。


解决方法如下：

在Oauth2 Server中自定义claim，类似如下代码

```java
@Bean
public OAuth2TokenCustomizer<OAuth2TokenClaimsContext> accessTokenCustomizer(){
    return context -> {
        OAuth2TokenClaimsSet.Builder claims = context.getClaims();
        claims.claim("customClaim", context.getPrincipal().getAuthorities());
        System.out.println(claims);
    };
}
```
资源服务器自定义NimbusOpaqueTokenIntrospector的子类，类似如下代码

```java
package com.itlab1024.oauth2resource.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.SneakyThrows;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONArray;
import net.minidev.json.JSONObject;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.RequestEntity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OAuth2IntrospectionAuthenticatedPrincipal;
import org.springframework.web.client.RestOperations;

import java.util.ArrayList;
import java.util.Collection;

@Slf4j
public class ITLabOpaqueTokenIntrospector extends NimbusOpaqueTokenIntrospector {

    public ITLabOpaqueTokenIntrospector(String introspectionUri, String clientId, String clientSecret) {
        super(introspectionUri, clientId, clientSecret);
    }

    public ITLabOpaqueTokenIntrospector(String introspectionUri, RestOperations restOperations) {
        super(introspectionUri, restOperations);
    }

    @SneakyThrows
    @Override
    public OAuth2AuthenticatedPrincipal introspect(String token) {
        OAuth2AuthenticatedPrincipal oAuth2AuthenticatedPrincipal = super.introspect(token);
        Collection<SimpleGrantedAuthority> authorities2 = (Collection<SimpleGrantedAuthority>) oAuth2AuthenticatedPrincipal.getAuthorities();
        Collection<GrantedAuthority> authorities = new ArrayList<>(authorities2);
        JSONArray jsonArray = oAuth2AuthenticatedPrincipal.getAttribute("customClaim");
        for (Object o : jsonArray) {
            JSONObject jsonObject = (JSONObject) o;
            Object authority = jsonObject.get("authority");
            authorities.add(new SimpleGrantedAuthority(authority.toString()));
        }
        log.info(new ObjectMapper().writeValueAsString(authorities2));
        return new OAuth2IntrospectionAuthenticatedPrincipal(oAuth2AuthenticatedPrincipal.getAttributes(), authorities);
    }

    @Override
    public void setRequestEntityConverter(Converter<String, RequestEntity<?>> requestEntityConverter) {
        super.setRequestEntityConverter(requestEntityConverter);
    }
}
```

资源服务器ResourceConfig里配置上刚才写的类。

```java
@Bean
public NimbusOpaqueTokenIntrospector opaqueTokenIntrospector() {
    return new ITLabOpaqueTokenIntrospector(oAuth2ResourceServerProperties.getOpaquetoken().getIntrospectionUri(), oAuth2ResourceServerProperties.getOpaquetoken().getClientId(), oAuth2ResourceServerProperties.getOpaquetoken().getClientSecret());
}

@Bean
public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
            .authorizeHttpRequests(authorize -> authorize
                    .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                    .opaqueToken(opaqueToken -> opaqueToken
                            .introspector(opaqueTokenIntrospector())
                    )
            );
    return http.build();
}
```