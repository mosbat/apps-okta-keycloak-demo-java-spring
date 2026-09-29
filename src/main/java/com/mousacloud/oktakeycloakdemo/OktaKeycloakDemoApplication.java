package com.mousacloud.oktakeycloakdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class OktaKeycloakDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(OktaKeycloakDemoApplication.class, args);
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ClientRegistrationRepository clients) throws Exception {

        var oidcLogout = new OidcClientInitiatedLogoutSuccessHandler(clients);
        oidcLogout.setPostLogoutRedirectUri("{baseUrl}/signed-out");

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/signed-out").permitAll()
                        .anyRequest().authenticated()
                )
                .oauth2Login(Customizer.withDefaults())
                .logout(logout -> logout.logoutSuccessHandler(oidcLogout));

        return http.build();
    }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public String home(
            @AuthenticationPrincipal OidcUser user,
            CsrfToken csrfToken) {

        return """
                <!doctype html>
                <html>
                  <body>
                    <p>Signed in as: %s (%s)</p>
                    <form action="/logout" method="post">
                      <input type="hidden" name="%s" value="%s">
                      <button type="submit">Log out</button>
                    </form>
                  </body>
                </html>
                """.formatted(
                escapeHtml(user.getFullName()),
                escapeHtml(user.getEmail()),
                escapeHtml(csrfToken.getParameterName()),
                escapeHtml(csrfToken.getToken()));
    }

    @GetMapping(value = "/signed-out", produces = MediaType.TEXT_HTML_VALUE)
    public String signedOut() {
        return "<!doctype html><html><body><p>Signed out</p></body></html>";
    }

    private static String escapeHtml(String value) {
        if (value == null) return "";
        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}