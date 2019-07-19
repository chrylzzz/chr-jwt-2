package com.chryl.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 2.创建两个注解，PassToken和UserLoginToken，用于在项目开发中，
 * 如果需要权限校验就标注userlogintoken，
 * 如果访问的资源不需要权限验证则正常编写不需要任何注解，
 * 如果用的的请求时登录操作，在用户登录的方法上增加passtoken注解。
 * <p>
 * Created By Chr on 2019/7/19.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface PassToken {
    boolean required() default true;
}
