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
     * 登录成功页面
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
        model.addAttribute("oauth2User",oauth2User);
        return "login-success";
    }

}
