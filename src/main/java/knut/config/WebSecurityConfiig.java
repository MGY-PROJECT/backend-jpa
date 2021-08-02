package knut.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
// Spring Security 구성을 위해 기본적으로 상속받아야하는 WebSecurityConfigurerAdapter
public class WebSecurityConfiig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        super.configure(auth);
    }

    @Bean
    // 패스워드 인코더.
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Override
    public void configure(WebSecurity web) { // 4
        web.ignoring().antMatchers("/css/**", "/js/**", "/img/**", "/lib/**","/h2-console/**");
        /*
         * The difference between /* & /** is that the second matches the entire directory tree,
         * including subdirectories, where as /* only matches at the level it's specified at.
         *
         * WebSecurityConfigurerAdapter를 상속받으면 오버라이드할 수 있습니다.
         * 인증을 무시할 경로들을 설정해놓을 수 있습니다.
         * static 하위 폴더 (css, js, img)는 무조건 접근이 가능해야하기 때문에 인증을 무시해야합니다.
         */
    }

    @Override
    // http 관련 인증 설정
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/login", "/signup").permitAll()          // 해당 페이지에 대해서는 허용
//                .antMatchers("/").hasRole("USER")                               // "/" 페이지에 대해서는 USER만 접근 가능
//                .antMatchers("/admin").hasRole("ADMIN")                // "/admin" 페이지에 대해서는 ADMIN만 접근 가능
                .anyRequest().authenticated();                                     // 상위 항목을 제외한 어느 요청에는 어느 권한이든 있어야 접근 가능.
//                .and()
//                    .exceptionHandling()
//                .and()
//                    .formLogin()                                                  // 로그인에 관한 설정
//                        .loginPage("/login")                                      // 로그인 페이지 링크 설정
//                        .defaultSuccessUrl("/")                                   // 로그인이 성공하면 리디렉트할 주소
//                .and()
//                    .logout()                                                     // 로그아웃에 관한 설정
//                        .logoutSuccessUrl("/login")                               // 로그아웃 성공하면 리디렉트할 주소
//                        .invalidateHttpSession(true);                             // 로그아웃 이후 세션 전체 삭제(true)
    }


}
