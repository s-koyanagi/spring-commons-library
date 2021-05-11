package com.kysh.commons.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;

@EnableWebSecurity
public class AuthConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    AuthEntryPoint authEntryPoint;

    @Autowired
    AuthDeniedHandler authDeniedHandler;

    @Autowired
    AuthSuccessHandler authSuccessHandler;

    @Autowired
    AuthFailureHandler authFailureHandler;

    @Autowired
    AuthService authService;

    @Override
    public void configure(WebSecurity web) {
        // セキュリティ設定を無視するリクエスト設定
        web.ignoring().antMatchers("/h2-console/**");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 埋め込みページ制御を無効化(h2-console用)
        http.headers().frameOptions().disable();
        // 認証周りの設定
        http.authorizeRequests()
                // 認証なしでアクセスできるURL
                .mvcMatchers("/test/hello").permitAll()
                // 認証済みでUSERロールを持っているユーザのみアクセスできるURL
                .mvcMatchers("/user/**").hasRole("USER")
                // 認証済みでADMINロールを持っているユーザのみユーザのみアクセスできるURL
                .mvcMatchers("/admin/**").hasRole("ADMIN")
                // その他のURLは認証済みであればアクセスできるURL
                .anyRequest().authenticated()
                .and()
                // アクセス時の例外処理
                .exceptionHandling()
                // 認証が必要なURLに未認証状態でアクセスした場合の処理
                .authenticationEntryPoint(authEntryPoint)
                // 認証済で権限がないURLへアクセスした場合の処理
                .accessDeniedHandler(authDeniedHandler)
                .and()
                // ログイン時の処理
                .formLogin()
                // ログインURLの設定
                .loginProcessingUrl("/login").permitAll()
                // ログインに必要なユーザ名パラメータの指定
                .usernameParameter("email")
                // ログインに必要なパスワードの設定
                .passwordParameter("password")
                // ログイン成功した場合の処理
                .successHandler(authSuccessHandler)
                // ログイン失敗した場合の処理
                .failureHandler(authFailureHandler)
                .and()
                // ログアウト時の処理
                .logout()
                // ログアウトURLの設定
                .logoutUrl("/logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                // ログアウトが正常終了した場合の処理
                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler())
                .and()
                // CSRFに関する処理
                .csrf()
                // CSRF無効設定
                .disable();
        // CSRFトークン例外設定
//                .ignoringAntMatchers("/login")
        // CSRFトークン付与の設定
//                .csrfTokenRepository(new CookieCsrfTokenRepository());
    }

    @Autowired
    void configureAuthenticationManager(AuthenticationManagerBuilder auth) throws Exception{
        auth.userDetailsService(authService).passwordEncoder(new BCryptPasswordEncoder());
    }
}
