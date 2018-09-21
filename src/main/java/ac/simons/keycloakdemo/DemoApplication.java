/*
 * Copyright 2017-2018 michael-simons.eu.
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

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

import java.security.Principal;
import java.util.Map;

import static org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter.DEFAULT_AUTHORIZATION_REQUEST_BASE_URI;

@SpringBootApplication
public class DemoApplication {
    public static void main(String... args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

/**
 * The "core" of this demo
 */
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
class SecurityConfig {

    /**
     * Configures OAuth Login with Spring Security 5.
     * @return
     */
    @Bean
    public WebSecurityConfigurerAdapter webSecurityConfigurer(
        @Value("${keycloak-client.registration-id}") final String registrationId
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
                        .loginPage(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/" + registrationId);
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
