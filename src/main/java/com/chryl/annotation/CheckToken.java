package com.chryl.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * 注解解析：从上面我们新建的两个类上我们可以看到主要的等学习到的就四点
 * 第一：如何创建一个注解
 * 第二：在我们自定义注解上新增@Target注解（注解解释：这个注解标注我们定义的注解是可以作用在类上还是方法上还是属性上面）
 * 第三：在我们自定义注解上新增@Retention注解（注解解释：作用是定义被它所注解的注解保留多久，一共有三种策略，SOURCE 被编译器忽略，CLASS  注解将会被保留在Class文件中，但在运行时并不会被VM保留。这是默认行为，所有没有用Retention注解的注解，都会采用这种策略。RUNTIME  保留至运行时。所以我们可以通过反射去获取注解信息。
 * 第四：boolean required() default true;  默认required() 属性为true
 * <p>
 * Created By Chr on 2019/7/19.
 */
@Target({ElementType.METHOD, ElementType.TYPE})
@Retention(RetentionPolicy.RUNTIME)
public @interface CheckToken {
    boolean required() default true;
}
