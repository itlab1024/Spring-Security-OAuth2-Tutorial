package io.github.itlab1024;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2TokenFormat;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;
import org.springframework.security.provisioning.UserDetailsManager;

import java.util.Set;
import java.util.UUID;
import java.util.function.Consumer;

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
        UserDetails userDetails = User.builder().passwordEncoder(s -> "{bcrypt}" + new BCryptPasswordEncoder().encode(s))
                .username("user")
                .password("password")
                .roles("ADMIN")
                .build();
        userDetailsManager.createUser(userDetails);
    }

    /**
     * 创建clientId信息
     */
    @Autowired
    private RegisteredClientRepository registeredClientRepository;

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
}
