package guo.ping.demo.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @description:
 * @author: guoping wang
 * @date: 2019/5/28 15:56
 * @project: spring-security-learn
 */
@RestController
@RequestMapping("/demo")
public class DemoController {

    @GetMapping("/hello")
    public String demo() {
        return "hello";
    }
}
