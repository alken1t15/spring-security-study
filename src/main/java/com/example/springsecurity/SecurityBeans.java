package com.example.springsecurity;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityBeans {

    @Bean
    SecurityFilterChain securityFilterChain(final HttpSecurity http) throws Exception{
        return http.authorizeHttpRequests(authorizeHttpRequests -> authorizeHttpRequests
                        .requestMatchers("/permit-all").permitAll()//Для всех
                        .requestMatchers("/deny-all").denyAll()//Нельзя получить доступ к этой странице
                                .requestMatchers("/anonymous").anonymous()//Только для анонимных пользователей
                                .requestMatchers("/authenticated").authenticated()//Только для авторизованных пользователей
                                .requestMatchers("/remember-me").rememberMe()//Для пользователей для долго живущих пользователей
                                .requestMatchers("/fully-authenticated").fullyAuthenticated()//Пользователи которые прошли полную авторизацию
                                .requestMatchers("/has-view-authority").hasAuthority("view")//У пользователя должно быть право view
                                .requestMatchers("/has-view-authority").hasAnyAuthority("update","delete")//У пользователя должно быть любое из этих прав
                                .requestMatchers("/has-view-authority").hasRole("admin")//У пользователя должно быть роль админ
                                .requestMatchers("/has-view-authority").hasAnyRole("customer","manager")//У пользователя должно быть роль customer или manager
                                .requestMatchers("/has-access").access((authentication,object) ->
                                        new AuthorizationDecision("c.norris".equals(authentication.get().getName())))

                                .requestMatchers(HttpMethod.GET, "/permit-all").permitAll()
                                .requestMatchers( "/api/*").permitAll()//Ограничение только для одного запроса
                                .requestMatchers( "/api/**").permitAll()//Ограничение для всех запросов
                                .requestMatchers( "/api/orders?search").permitAll()//Можно подставлять условия в путь
                        )
                .build();
    }
}
