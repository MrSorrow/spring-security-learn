package guo.ping.security.browser;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/5/28 20:34
 * @project: spring-security-learn
 */
@Configuration
public class BrowserSecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.formLogin() // 所有的请求都需要表单登录进行认证
//        http.httpBasic() // 所有的请求都需要弹框式表单登录进行认证
            .and()
            .authorizeRequests()  // 对请求进行授权
            .anyRequest()  // 对任何请求
            .authenticated();  // 进行授权
    }
}
