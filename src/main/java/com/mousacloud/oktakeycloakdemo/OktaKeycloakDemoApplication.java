package com.mousacloud.oktakeycloakdemo;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
@RestController
public class OktaKeycloakDemoApplication {

    @Value("${APP_NAME:Okta-Keycloak IAM Demo}")
    private String appName;

    @Value("${ADMIN_GROUP:demo-app-a-admin}")
    private String adminGroup;

    public static void main(String[] args) {
        SpringApplication.run(OktaKeycloakDemoApplication.class, args);
    }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            ClientRegistrationRepository clients,
            GrantedAuthoritiesMapper authoritiesMapper) throws Exception {

        var oidcLogout = new OidcClientInitiatedLogoutSuccessHandler(clients);
        oidcLogout.setPostLogoutRedirectUri("{baseUrl}/signed-out");

        http
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/signed-out", "/access-denied").permitAll()
                        .requestMatchers("/admin").hasAuthority("GROUP_" + adminGroup)
                        .anyRequest().authenticated()
                )
                .oauth2Login(oauth2 -> oauth2
                        .userInfoEndpoint(userInfo -> userInfo
                                .userAuthoritiesMapper(authoritiesMapper)
                        )
                )
                .exceptionHandling(exceptions -> exceptions
                        .accessDeniedPage("/access-denied")
                )
                .logout(logout -> logout.logoutSuccessHandler(oidcLogout));

        return http.build();
    }

    @Bean
    GrantedAuthoritiesMapper authoritiesMapper() {
        return authorities -> {
            Set<GrantedAuthority> mappedAuthorities = authorities.stream()
                    .collect(Collectors.toSet());

            authorities.stream()
                    .filter(OidcUserAuthority.class::isInstance)
                    .map(OidcUserAuthority.class::cast)
                    .map(authority -> authority.getIdToken()
                            .getClaimAsStringList("groups"))
                    .filter(groups -> groups != null)
                    .flatMap(Collection::stream)
                    .filter(group -> group.startsWith("demo-app-"))
                    .map(group -> new SimpleGrantedAuthority("GROUP_" + group))
                    .forEach(mappedAuthorities::add);

            return mappedAuthorities;
        };
    }

    @GetMapping(value = "/", produces = MediaType.TEXT_HTML_VALUE)
    public String home(
            @AuthenticationPrincipal OidcUser user,
            CsrfToken csrfToken) {

        List<String> groups = user.getClaimAsStringList("groups");

        return """
                <!doctype html>
                <html lang="en">
                  <head>
                    <meta charset="UTF-8">
                    <title>%s</title>
                  </head>
                  <body>
                    <h1>%s</h1>
                    <p>Federated SSO successful</p>
                    <p>Signed in as: %s (%s)</p>
                
                    <h2>Authorization context</h2>
                    <p>Groups from the Okta ID token: %s</p>
                
                    <p><a href="/admin">Attempt privileged admin action</a></p>
                    <p><a href="/whoami">View safe identity details as JSON</a></p>
                
                    <form action="/logout" method="post">
                      <input type="hidden" name="%s" value="%s">
                      <button type="submit">Log out</button>
                    </form>
                  </body>
                </html>
                """.formatted(
                escapeHtml(appName),
                escapeHtml(appName),
                escapeHtml(user.getFullName()),
                escapeHtml(user.getEmail()),
                escapeHtml(groups == null ? "[]" : groups.toString()),
                escapeHtml(csrfToken.getParameterName()),
                escapeHtml(csrfToken.getToken()));
    }

    @GetMapping(value = "/admin", produces = MediaType.TEXT_HTML_VALUE)
    public String admin(@AuthenticationPrincipal OidcUser user) {
        return """
                <!doctype html>
                <html lang="en">
                  <head>
                    <meta charset="UTF-8">
                    <title>%s — Privileged Area</title>
                  </head>
                  <body>
                    <h1>%s — Privileged action permitted</h1>
                    <p>User %s holds the <code>demo-app-admin</code> entitlement.</p>
                    <p>
                      This route is protected by local Spring Security authorization
                      after federated authentication through Keycloak and Okta.
                    </p>
                    <p><a href="/">Return to home</a></p>
                  </body>
                </html>
                """.formatted(
                escapeHtml(appName),
                escapeHtml(appName),
                escapeHtml(user.getEmail()));
    }

    @GetMapping(value = "/access-denied", produces = MediaType.TEXT_HTML_VALUE)
    public String accessDenied() {
        return """
                <!doctype html>
                <html lang="en">
                  <head>
                    <meta charset="UTF-8">
                    <title>%s — Access denied</title>
                  </head>
                  <body>
                    <h1>%s — 403 Access denied</h1>
                    <p>
                      You authenticated successfully, but do not have the
                      <code>demo-app-admin</code> entitlement required for
                      this privileged function.
                    </p>
                    <p><a href="/">Return to home</a></p>
                  </body>
                </html>
                """.formatted(
                escapeHtml(appName),
                escapeHtml(appName));
    }

    @GetMapping(value = "/whoami", produces = MediaType.APPLICATION_JSON_VALUE)
    public Map<String, Object> whoAmI(
            @AuthenticationPrincipal OidcUser user,
            org.springframework.security.core.Authentication authentication) {

        Map<String, Object> result = new LinkedHashMap<>();
        result.put("application", appName);
        result.put("subject", user.getSubject());
        result.put("name", user.getFullName());
        result.put("email", user.getEmail());
        result.put("groups", user.getClaimAsStringList("groups"));
        result.put("authorities", authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .sorted()
                .toList());

        return result;
    }

    @GetMapping(value = "/signed-out", produces = MediaType.TEXT_HTML_VALUE)
    public String signedOut() {
        return """
                <!doctype html>
                <html lang="en">
                  <head>
                    <meta charset="UTF-8">
                    <title>%s — Signed out</title>
                  </head>
                  <body>
                    <h1>%s</h1>
                    <p>Signed out successfully.</p>
                    <p><a href="/">Sign in again</a></p>
                  </body>
                </html>
                """.formatted(
                escapeHtml(appName),
                escapeHtml(appName));
    }

    private static String escapeHtml(String value) {
        if (value == null) {
            return "";
        }

        return value.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#39;");
    }
}