# Spring Security
Spring Security的核心功能：认证、授权和攻击防护

## 工程结构

1. spring-security-learn 父工程
2. spring-security-core 核心模块
3. spring-security-browser 浏览器模块，依赖核心模块
4. spring-security-app 移动端模块，依赖核心模块
5. spring-security-demo 样例工程，依赖浏览器模块与App模块

## 基于表单的认证
基于表单的认证包含用户名密码、短信验证码两种模式。默认情况下，Spring Security会将所有的请求资源全部保护起来，用户需要用用户名密码进行认证才能访问资源。

**Spring Security基本原理**

Spring Security实现是靠Filter实现的，在请求真正达到资源之前，先经过层层过滤器组成的过滤器链，然后才能访问保护的资源。如下所示：

绿色的代表对用户身份信息认证的过滤器链，每一个过滤器负责处理一种认证方式，检查请求中是否包含该过滤器所需要的信息。如果认证成功，过滤器会设置标记，认证失败则交由下一个过滤器验证。

黄色的过滤器 `FilterSecurityInterceptor` 的作用是整个链的最后一关，会根据系统设置的认真规则去判断前面相应的绿色拦截器是否认证通过。如果不含有对应要求的那一种认证成功标记，则会抛出对应异常。

异常则会由蓝色过滤器 `ExceptionTranslationFilter` 捕获，该过滤器主要用于接收 `FilterSecurityInterceptor` 抛出的异常，并引导用户去输入验证信息进行登录认证。

![Spring Security过滤器链](E:\IDEA\spring-security-learn\readme.assets\1559110793113.png)

### 用户名密码模式

**自定义用户认证逻辑**

默认的用户名是 `user`，密码是每次系统启动随机生成的，这种方式显然是不常用的。通常我们的用户信息都是从数据库进行获取并校验的。自定义用户认证逻辑可以通过 `UserDetailsService` 接口来实现。自己编写的 `UserDetailsService` 接口的实现类只需要通过注解添加到Spring容器中即可。

```java
@Component
public class MyUserDetailsService implements UserDetailsService {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private BCryptPasswordEncoder bCryptPasswordEncoder;

    /**
     * 模拟从数据库中依据username查询具体的用户信息
     * @param username
     * @return
     * @throws UsernameNotFoundException
     */
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        logger.info("start query user info from db by username = " + username);
        // 第一次需要对用户的密码进行加密
        String password = bCryptPasswordEncoder.encode("123456");
        logger.info("query user password = " + password);

        // 这个User对象时Spring中提供的，已经实现了UserDetails接口，UserDetails接口包含了用户的名称、密码、密码是否过期、账户是否冻结、是否删除、所拥有的权限等信息
        // 我们自己写业务逻辑时，返回的User bean可以自己实现UserDetails接口
        return new User(username, password, true,true,true,true, AuthorityUtils.commaSeparatedStringToAuthorityList("admin"));
    }
}
```

**个性化用户认证流程**

通常项目中我们都会使用自己的登录页面，所以需要配置自定义的登陆页。同时登录成功与登录失败，可能不仅仅是默认的跳转动作那么简单，可能需要额外添加日志等等逻辑，那么需要我们自定义登录成功与失败的逻辑。

自定义跳转的登录页逻辑：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
        .loginPage("/signIn.html")  // 指定登录页
        .loginProcessingUrl("/authentication/form") // 指定登录表单信息提交处理请求，和登录页面中的需一致
        .and()
        .authorizeRequests()
        .antMatchers("/signIn.html").permitAll() // 登录页无需认证
        .anyRequest()
        .authenticated()
        .and()
        .csrf().disable(); // 屏蔽跨站请求伪造
}
```

自定义登陆页面：

```html
<form action="/authentication/form" method="post">
    <table>
        <tr>
            <td>用户名:</td> 
            <td><input type="text" name="username"></td>
        </tr>
        <tr>
            <td>密码:</td>
            <td><input type="password" name="password"></td>
        </tr>
        <tr>
            <td colspan="2"><button type="submit">登录</button></td>
        </tr>
    </table>
</form>
```

自定义登录成功逻辑主要编写 `AuthenticationSuccessHandler` 接口的实现类：

```java
@Component
public class MyAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private ObjectMapper objectMapper;

    // Authentication封装了认证信息，包括认证请求的session、ip，认证成功的用户信息等
    @Override
    public void onAuthenticationSuccess(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, Authentication authentication) throws IOException, ServletException {
        logger.info("登录成功");
        logger.info("authentication 包含 " + objectMapper.writeValueAsString(authentication));
    }
}
```

自定义登录失败逻辑主要编写 `AuthenticationFailureHandler` 接口的实现类：

```java
@Component
public class MyAuthenticationFailureHandler implements AuthenticationFailureHandler {

    private Logger logger = LoggerFactory.getLogger(getClass());

    @Autowired
    private ObjectMapper objectMapper;

    @Override
    public void onAuthenticationFailure(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, AuthenticationException e) throws IOException, ServletException {
        logger.info("登录失败");
        logger.info("authentication 包含 " + objectMapper.writeValueAsString(e));
    }
}
```

注册自定义的登录成功与失败处理器：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    http.formLogin()
        .loginPage("/user/login")
        .loginProcessingUrl("/user/authentication")
        .successHandler(myAuthenticationSuccessHandler)  // 登录成功
        .failureHandler(myAuthenticationFailureHandler)  // 登录失败
        .and()
        .authorizeRequests()
        .antMatchers("/user/login", securityProperties.getBrowser().getLoginPage()).permitAll()
        .anyRequest()
        .authenticated()
        .and()
        .csrf().disable();
}
```



### 短信验证码模式