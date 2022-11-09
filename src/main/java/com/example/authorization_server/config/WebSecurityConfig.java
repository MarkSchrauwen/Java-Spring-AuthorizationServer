package com.example.authorization_server.config;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;

import lombok.AllArgsConstructor;

@Configuration
@AllArgsConstructor
public class WebSecurityConfig {

    private final CORSCustomizer corsCustomizer;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{
        corsCustomizer.corsCustomizer(http);
        return http.formLogin()
            .and()
        .authorizeRequests()
            .anyRequest().authenticated()
        .and().build();
    }

    @Bean
    public UserDetailsService userDetailsService() {
        var u1 = User.withUsername("mark").password("12345").authorities("read").build();
        var uds = new InMemoryUserDetailsManager();
        uds.createUser(u1);
        return uds;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        // return new BCryptPasswordEncoder(); this to be used in real world application
        return NoOpPasswordEncoder.getInstance(); // this only for demo's
    }
}
