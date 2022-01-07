package com.boots.config;

import com.boots.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    @Autowired
    UserService userService;

    @Bean
    public BCryptPasswordEncoder bCryptPasswordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf()
                    .disable()
                .authorizeRequests()
                    //Faqat ro'yxatdan o'tmagan foydalanuvchilar uchun ruxsat
                    .antMatchers("/registration").not().fullyAuthenticated()
                    //Faqat Administrator roliga ega foydalanuvchilar uchun ruxsat
                    .antMatchers("/admin/**").hasRole("ADMIN")
                    .antMatchers("/news").hasRole("USER")
                    //Kirish barcha foydalanuvchilarga ruxsat etiladi
                    .antMatchers("/", "/resources/**").permitAll()
                //Boshqa barcha sahifalar autentifikatsiyani talab qiladi
                .anyRequest().authenticated()
                .and()
                    //Kirish sozlamalari
                    .formLogin()
                    .loginPage("/login")
                    //Muvaffaqiyatli tizimga kirgandan so'ng bosh sahifaga yo'naltirilmoqda
                    .defaultSuccessUrl("/")
                    .permitAll()
                .and()
                    .logout()
                    .permitAll()
                    .logoutSuccessUrl("/");
    }

    @Autowired
    protected void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userService).passwordEncoder(bCryptPasswordEncoder());
    }
}
