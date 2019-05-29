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

### 短信验证码模式