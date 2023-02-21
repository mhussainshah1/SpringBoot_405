package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {
    @Autowired
    private SSUserDetailsService userDetailsService;

    @Autowired
    private UserRepository appUserRepository;

    @Bean
    public static BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests()
                .requestMatchers("/", "/h2-console/**").permitAll() //.hasAnyRole("USER", "ADMIN")
                .requestMatchers("/admin").hasRole("ADMIN")//.hasAuthority("ROLE_ADMIN")
                .anyRequest().authenticated()

                .and()

                .formLogin()
                .loginPage("/login").permitAll()

                .and()

                .logout()
                .logoutUrl("/logout")//.logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login?logout").permitAll()

                .and()

                .httpBasic(Customizer.withDefaults());
        http
                .csrf().disable();
        http
                .headers().frameOptions().disable();
        return http.build();
    }

    @Bean
    public AuthenticationProvider userDetailsServiceBean(BCryptPasswordEncoder passwordEncoder) {
        userDetailsService = new SSUserDetailsService(appUserRepository);
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }
}
