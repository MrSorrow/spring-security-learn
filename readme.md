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

**表单认证的原理**



![1559185687245](E:\IDEA\spring-security-learn\readme.assets\1559185687245.png)

**用户认证信息存储Session**

用户认证得到的 `Authentication` 信息会被存储到 `SecurityContext` 中。

![用户认证信息存储Session](E:\IDEA\spring-security-learn\readme.assets\1559222340513.png)



`SecurityContextPersistenceFilter` 过滤器负责将用户认证信息存入Session。其位于过滤器链的最前端，也就是请求进入与响应出口都经过该过滤器。在**请求进入**时，它负责查看 `SecurityContext` 中是否含有认证信息，如果有就添加到 `SecurityContextHolder` 这个 `ThreadLocal` 中，没有则继续执行过滤器链；在**返回响应**时，检查线程中是否有认证信息，有认证信息则放入 `SecurityContext` 中。这样所有请求都会共享 `SecurityContext` 中的用户认证信息。

![SecurityContextPersistenceFilter](E:\IDEA\spring-security-learn\readme.assets\1559222383495.png)



**获取认证用户信息**

通常认证成功的用户，我们会需要获取使用，所以Spring提供了对应参数解析器，直接能够获取到 `Authentication` 信息。

```java
@GetMapping("/me")
public Object getCurrentUser(UserDetails user) {
    return user;
}
```

当然从上面用户信息存储Session的过程，我们也可以手动获取：

```java
@GetMapping("/me")
public Object getCurrentUser() {
    return SecurityContextHolder.getContext().getAuthentication();
}
```

默认返回的 `Authentication` 信息包含了很多内容，可能我们仅仅想要其中的 `UserDetails`，`@AuthenticationPrincipal` 注解可以帮助我们：

```java
@GetMapping("/me")
public Object getCurrentUser(@AuthenticationPrincipal UserDetails user) {
    return user;
}
```

**图片验证码**

生成图片二维码方法：

```java
@Controller
public class ValidateCodeController {

    private static final String SESSION_KEY = "SESSION_KEY_IMAGE_CODE";

    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    @GetMapping("/code/image")
    public void createCode(HttpServletRequest request, HttpServletResponse response) throws IOException {
        ImageCode imageCode = createImageCode(request);
        // 将二维码存入Session中，用于和用户输入校验
        sessionStrategy.setAttribute(new ServletWebRequest(request), SESSION_KEY, imageCode);
        // 将二维码图片写入response中
        ImageIO.write(imageCode.getImage(), "JPEG", response.getOutputStream());
    }

    private ImageCode createImageCode(HttpServletRequest request) {
        int width = 67;
        int height = 23;
        BufferedImage image = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);

        Graphics g = image.getGraphics();

        Random random = new Random();

        g.setColor(getRandColor(200, 250));
        g.fillRect(0, 0, width, height);
        g.setFont(new Font("Times New Roman", Font.ITALIC, 20));
        g.setColor(getRandColor(160, 200));
        for (int i = 0; i < 155; i++) {
            int x = random.nextInt(width);
            int y = random.nextInt(height);
            int xl = random.nextInt(12);
            int yl = random.nextInt(12);
            g.drawLine(x, y, x + xl, y + yl);
        }

        String sRand = "";
        for (int i = 0; i < 4; i++) {
            String rand = String.valueOf(random.nextInt(10));
            sRand += rand;
            g.setColor(new Color(20 + random.nextInt(110), 20 + random.nextInt(110), 20 + random.nextInt(110)));
            g.drawString(rand, 13 * i + 6, 16);
        }

        g.dispose();

        return new ImageCode(image, sRand, 60);
    }

    /**
     * 生成随机背景条纹
     * @param fc
     * @param bc
     * @return
     */
    private Color getRandColor(int fc, int bc) {
        Random random = new Random();
        if (fc > 255) {
            fc = 255;
        }
        if (bc > 255) {
            bc = 255;
        }
        int r = fc + random.nextInt(bc - fc);
        int g = fc + random.nextInt(bc - fc);
        int b = fc + random.nextInt(bc - fc);
        return new Color(r, g, b);
    }
}
```

**校验二维码内容是否匹配**

自定义验证码过滤器：

```java
public class ValidateCodeFilter extends OncePerRequestFilter {
    // OncePerRequestFilter是Spring提供的工具类，保证过滤器每次只调用一次

    private AuthenticationFailureHandler myAuthenticationFailureHandler;

    private SessionStrategy sessionStrategy = new HttpSessionSessionStrategy();

    public void setMyAuthenticationFailureHandler(AuthenticationFailureHandler myAuthenticationFailureHandler) {
        this.myAuthenticationFailureHandler = myAuthenticationFailureHandler;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain)
            throws ServletException, IOException {
        // 如果是用户认证请求，才会去校验验证码逻辑，否则直接放行
        if (StringUtils.equals("/user/authentication", httpServletRequest.getRequestURI())
                && StringUtils.equalsIgnoreCase(httpServletRequest.getMethod(), "post")) {

            try {
                validate(new ServletWebRequest(httpServletRequest));
                logger.info("验证码校验通过");
            } catch (ValidateCodeException exception) {
                myAuthenticationFailureHandler.onAuthenticationFailure(httpServletRequest, httpServletResponse, exception);
                return;
            }
        }

        // 只有验证成功，才继续放行
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }

    private void validate(ServletWebRequest servletWebRequest) throws ServletRequestBindingException {
        ImageCode codeInSession = (ImageCode) sessionStrategy.getAttribute(servletWebRequest, ValidateCodeController.SESSION_KEY);

        String codeInRequest = ServletRequestUtils.getStringParameter(servletWebRequest.getRequest(), "imageCode");

        if (StringUtils.isBlank(codeInRequest)) {
            throw new ValidateCodeException("验证码的值不能为空");
        }

        if (codeInSession == null) {
            throw new ValidateCodeException("验证码不存在");
        }

        if (codeInSession.isExpried()) {
            sessionStrategy.removeAttribute(servletWebRequest, ValidateCodeController.SESSION_KEY);
            throw new ValidateCodeException("验证码已过期");
        }

        if (!StringUtils.equals(codeInSession.getCode(), codeInRequest)) {
            throw new ValidateCodeException("验证码不匹配");
        }

        sessionStrategy.removeAttribute(servletWebRequest, ValidateCodeController.SESSION_KEY);
    }
}
```

在表单登录过滤器 `UsernamePasswordAuthenticationFilter` 前添加上一个验证码过滤器：

```java
 @Override
protected void configure(HttpSecurity http) throws Exception {
    ValidateCodeFilter validateCodeFilter = new ValidateCodeFilter();
    validateCodeFilter.setMyAuthenticationFailureHandler(myAuthenticationFailureHandler);

    // 在表单登录过滤器前添加上一个验证码过滤器
    http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
        .formLogin()
        .loginPage("/user/login")
        .loginProcessingUrl("/user/authentication")
        .successHandler(myAuthenticationSuccessHandler)
        .failureHandler(myAuthenticationFailureHandler)
        .and()
        .authorizeRequests()
        .antMatchers("/user/login", securityProperties.getBrowser().getLoginPage(), "/code/image").permitAll()
        .anyRequest()
        .authenticated()
        .and()
        .csrf().disable();
}
```

**记住我功能**

当通过表单认证成功后，会利用 `RememberMeService` 生成一个随机 Token 写入浏览器Cookie中，并通过 `TokenRepository` 将 Token 和 认证信息的 `userId` 对应存入数据库中。当服务请求时，会经过过滤器链中的 `RememberMeAuthenticationFilter` 过滤器根据Cookie的 Token 值去数据库查询用户信息。

![记住我](E:\IDEA\spring-security-learn\readme.assets\1559368746482.png)

表单上需要添加一个固定 `name=remember-me` 的勾选框：

```html
<tr>
    <td colspan="2">
        <input type="checkbox" name="remember-me" value="true">记住我
    </td>
</tr>
```

注入 `PersistentTokenRepository` 进入Spring容器：

```java
@Autowired
private DataSource dataSource;

@Bean
public PersistentTokenRepository persistentTokenRepository() {
    JdbcTokenRepositoryImpl jdbcTokenRepository = new JdbcTokenRepositoryImpl();
    jdbcTokenRepository.setDataSource(dataSource);
    return jdbcTokenRepository;
}
```

配置记住我相关配置：

```java
@Override
protected void configure(HttpSecurity http) throws Exception {
    ValidateCodeFilter validateCodeFilter = new ValidateCodeFilter();
    validateCodeFilter.setMyAuthenticationFailureHandler(myAuthenticationFailureHandler);

    http.addFilterBefore(validateCodeFilter, UsernamePasswordAuthenticationFilter.class)
            .formLogin()
            .loginPage("/user/login")
            .loginProcessingUrl("/user/authentication")
            .successHandler(myAuthenticationSuccessHandler)
            .failureHandler(myAuthenticationFailureHandler)
        .and()
        	// 记住我
            .rememberMe()
        	// TokenRepository
            .tokenRepository(persistentTokenRepository())
        	// 过期时间
            .tokenValiditySeconds(securityProperties.getBrowser().getRememberMeSeconds())
            // UserDetailsService
        	.userDetailsService(myUserDetailsService)
        .and()
            .authorizeRequests()
            .antMatchers("/user/login", securityProperties.getBrowser().getLoginPage(), "/code/image").permitAll()
            .anyRequest()
            .authenticated()
        .and()
        	.csrf().disable();
}
```

运行测试，勾选 `remember-me` 复选框，会在数据库中插入记录。

![自动生成的表名称](E:\IDEA\spring-security-learn\readme.assets\1559374760331.png)

### 短信验证码模式

**生成短信验证码**

类似生成图片数字验证码一样，原理比数字验证码更简单一些。

**短信验证码认证流程**

参考表单认证方式，表单登录的请求会经过 `UsernamePasswordAuthenticationFilter` 过滤器，过滤器会将输入的用户名密码组装成一个 `UsernamePasswordAuthenticationToken` 的 TOKEN，将其传给 `AuthenticationManager`， `AuthenticationManager` 会从一堆 `xxxProviders` 中去寻找 `support` 该 TOKEN 类型的 `DaoAuthenticationProvider`。`DaoAuthenticationProvider` 会具体的认证输入的用户信息是否正确。

![表单登录方式](E:\IDEA\spring-security-learn\readme.assets\1559375696333.png)

依照表单认证流程，短信验证方式也可以进行同样的设计。我们设计一个新的过滤器 `SmsAuthenticationFilter`，用于短信方式认证。它将用户输入的手机号信息封装成自定义的 `SmsAuthenticationToken`，配套定义一个 `support` 该 TOKEN 类型的 `SmsAuthenticationProvider`。

![短信验证方式](E:\IDEA\spring-security-learn\readme.assets\1559376348604.png)

关于验证短信验证码的正确与否逻辑，则可以完全参照图形验证码逻辑，在过滤器链前面添加一个新的校验验证码的过滤器。

