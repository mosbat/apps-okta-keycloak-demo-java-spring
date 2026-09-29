package com.mousacloud.oktakeycloakdemo;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class OktaKeycloakDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(OktaKeycloakDemoApplication.class, args);
    }

    @GetMapping("/")
    public String home(@AuthenticationPrincipal OidcUser user) {
        return "Signed in as: " + user.getFullName()
                + " (" + user.getEmail() + ")";
    }
}
