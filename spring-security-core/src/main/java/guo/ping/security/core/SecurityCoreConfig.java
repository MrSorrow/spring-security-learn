package guo.ping.security.core;

import guo.ping.security.core.properties.SecurityProperties;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/5/29 21:00
 * @project: spring-security-learn
 */
@Configuration
@EnableConfigurationProperties(SecurityProperties.class) // 让properties读取器生效
public class SecurityCoreConfig {
}
