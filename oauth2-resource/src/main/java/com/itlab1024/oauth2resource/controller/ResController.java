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
