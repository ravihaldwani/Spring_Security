//package com.example.demo.security;
//
//import static com.example.demo.security.ApplicationUserRole.STUDENT;
//
//import java.util.concurrent.TimeUnit;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
//import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
//import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
//import org.springframework.security.config.annotation.web.builders.HttpSecurity;
//import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
//import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
//import org.springframework.security.crypto.password.PasswordEncoder;
//import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
//
//import com.example.demo.auth.ApplicationUserService;
//
//
//@Configuration
//@EnableWebSecurity
//@EnableGlobalMethodSecurity(prePostEnabled =  true)
//public class ApplicationSecurityConfig2 extends WebSecurityConfigurerAdapter {
//
//    private final PasswordEncoder passwordEncoder;
//    private final ApplicationUserService applicationUserService;
//    @Autowired
//    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder,ApplicationUserService applicationUserService) {
//        this.passwordEncoder = passwordEncoder;
//        this.applicationUserService = applicationUserService;
//    }
//
//    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http	
////        		.csrf().csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
////        		.and()
//        		.csrf().disable()
//                .authorizeRequests()
//                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
//                .antMatchers("/api/**").hasRole(STUDENT.name())
////                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ADMIN.name(),ADMINTRAINEE.name())
////                .antMatchers(HttpMethod.POST, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
////                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
//               
//                .anyRequest()
//                .authenticated()
//                .and()
//                .formLogin()
//                .loginPage("/login")
//                .permitAll()
//                .defaultSuccessUrl("/courses", true)
//                .passwordParameter("password")
//                .usernameParameter("username")
//            .and()
//            .rememberMe()
//                .tokenValiditySeconds((int) TimeUnit.DAYS.toSeconds(21))
//                .key("somethingverysecured")
//                .rememberMeParameter("remember-me")
//            .and()
//            .logout()
//                .logoutUrl("/logout")
//                .logoutRequestMatcher(new AntPathRequestMatcher("/logout", "GET")) // https://docs.spring.io/spring-security/site/docs/4.2.12.RELEASE/apidocs/org/springframework/security/config/annotation/web/configurers/LogoutConfigurer.html
//                .clearAuthentication(true)
//                .invalidateHttpSession(true)
//                .deleteCookies("JSESSIONID", "remember-me")
//                .logoutSuccessUrl("/login");
//        		
//    }
//    
//    @Override
//    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
//        auth.authenticationProvider(daoAuthenticationProvider());
//    }
//
//    @Bean
//    public DaoAuthenticationProvider daoAuthenticationProvider() {
//        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
//        provider.setPasswordEncoder(passwordEncoder);
//        provider.setUserDetailsService(applicationUserService);
//        return provider;
//    }
//    
//
////    @Override
////    @Bean
////    protected UserDetailsService userDetailsService() {
////        UserDetails annaSmithUser = User.builder()
////                .username("annasmith")
////                .password(passwordEncoder.encode("password"))
//////              .roles(STUDENT.name()) // ROLE_STUDENT
////                .authorities(STUDENT.getGrantedAuthorities())
////                .build();
////
////        UserDetails lindaUser = User.builder()
////                .username("linda")
////                .password(passwordEncoder.encode("password123"))
//////              .roles(ADMIN.name()) // ROLE_ADMIN
////                .authorities(ADMIN.getGrantedAuthorities())
////                .build();
////
////        UserDetails tomUser = User.builder()
////                .username("tom")
////                .password(passwordEncoder.encode("password123"))
//////              .roles(ADMINTRAINEE.name()) // ROLE_ADMINTRAINEE	
////                .authorities(ADMINTRAINEE.getGrantedAuthorities())
////                .build();
////
////        return new InMemoryUserDetailsManager(
////        		annaSmithUser,
////                lindaUser,
////                tomUser
////        );
////
////    }
//}
