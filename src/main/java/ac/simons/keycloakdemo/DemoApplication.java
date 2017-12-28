/*
 * Copyright 2017 michael-simons.eu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ac.simons.keycloakdemo;

import lombok.Data;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.SecurityAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

/**
 * Spring Boot Security 2 backs off anyway if there's at least one bean of type
 * WebSecurityConfigurerAdapter, but it still generates an in-memory user and I
 * don't want this and therefor I'm excluding the whole auto config.
 */
@SpringBootApplication(exclude = SecurityAutoConfiguration.class)
public class DemoApplication {
    public static void main(String... args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

/**
 * Basic property class that wraps up all properties relevant
 * to one Keycloak realm.
 */
@Data
@ConfigurationProperties(prefix = "keycloak-client")
class KeycloakClientProperties {
    private String id;

    private String secret;

    private String name;

    private Set<String> scopes = Collections.emptySet();

    private String serverUrl;

    private String realm;

    /**
     * And this is the only interesting part here. The keycloak realm
     * is transformed to a so called ClientRegistration. ClientRegistrations
     * are used by Spring Security 5 to define different OAuth providers
     * @return
     */
    public ClientRegistration asClientRegistration() {
        final String openIdConnectBaseUri
            = this.serverUrl + "/realms/" + this.realm + "/protocol/openid-connect";
        return ClientRegistration.withRegistrationId(this.realm)
            .clientId(this.id)
            .clientSecret(this.secret)
            .clientName(this.name)
            .clientAuthenticationMethod(ClientAuthenticationMethod.BASIC)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .redirectUriTemplate("{baseUrl}/login/oauth2/code/{registrationId}")
            .scope(this.scopes.toArray(new String[0]))
            .authorizationUri(openIdConnectBaseUri + "/auth")
            .tokenUri(openIdConnectBaseUri + "/token")
            .jwkSetUri(openIdConnectBaseUri + "/certs")
            .userInfoUri(openIdConnectBaseUri + "/userinfo")
            // Use a sane username from the JWT
            .userNameAttributeName("preferred_username")
            .build();
    }
}

/**
 * The "core" of this demo
 */
@Configuration
// We have to enable this manually as I excluded auto config for security
@EnableWebSecurity
// Yeah, more Annotations!
@EnableGlobalMethodSecurity(prePostEnabled = true)
// enable the above property class
@EnableConfigurationProperties(KeycloakClientProperties.class)
class SecurityConfig {

    /**
     * This repository contains all known client registrations. THis is only one-
     * Fan-out to different clients is done by Keycloak if necessary.
     *
     * @param clientProperties
     * @return
     */
    @Bean
    public ClientRegistrationRepository clientRegistrationRepository(
            final KeycloakClientProperties clientProperties
    ) {
        return new InMemoryClientRegistrationRepository(
            clientProperties.asClientRegistration());
    }

    /**
     * Configures OAuth Login with Spring Security 5.
     * @param clientProperties
     * @return
     */
    @Bean
    public WebSecurityConfigurerAdapter webSecurityConfigurer(
        final KeycloakClientProperties clientProperties
    ) {
        return new WebSecurityConfigurerAdapter() {
            @Override
            public void configure(HttpSecurity http) throws Exception {
                http
                    // Configure session management to your needs.
                    // I need this as a basis for a classic, server side rendered application
                    .sessionManagement()
                        .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
                        .and()
                    // Depends on your taste. You can configure single paths here
                    // or allow everything a I did and then use method based security
                    // like in the controller below
                    .authorizeRequests()                       
                        .anyRequest().permitAll()
                        .and()
                    // This is the point where OAuth2 login of Spring 5 gets enabled
                    .oauth2Login()
                        // I don't want a page with different clients as login options
                        // So i use the constant from OAuth2AuthorizationRequestRedirectFilter
                        // plus the configured realm as immediate redirect to Keycloak
                        .loginPage(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/" + clientProperties.getRealm());
            }
        };
    }    
}

/**
 * Just a demo.
 */
@Controller
class DemoController {

    // See, I am a fan of method level security
    @PreAuthorize("isAuthenticated()")
    @GetMapping(path = "/protected")
    public ModelAndView protectedPage(final Principal principal) {
        return new ModelAndView("index", Map.of("principal", principal));
    }

    @GetMapping(path = "/unprotected")
    public String unprotectedPage() {
        return "index";
    }
}
