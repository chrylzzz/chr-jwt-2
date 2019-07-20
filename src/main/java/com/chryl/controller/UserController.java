package com.chryl.controller;

import com.alibaba.fastjson.JSONObject;
import com.chryl.annotation.CheckToken;
import com.chryl.annotation.PassToken;
import com.chryl.bean.User;
import com.chryl.mapper.UserMapper;
import com.chryl.utils.JwtUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

/**
 * 使用postman
 * <p>
 * Created By Chr on 2019/7/19.
 */
@RestController
@RequestMapping("/v1/user")
public class UserController {
    @Autowired
    private UserMapper userMapper;

    //登陆不验证jwt,只生成jwt
    @PassToken
    @PostMapping(value = "/login")
    public Object login(@RequestParam("username") String username,
                        @RequestParam("password") String password) {

        JSONObject jsonObject = new JSONObject();
        User user = userMapper.selectByUserName(username);
        if (user == null) {
            jsonObject.put("message", "登录失败,用户不存在");
            return jsonObject;
        } else {
            if (!password.equals(user.getUserPassword())) {
                jsonObject.put("message", "登录失败");
                return jsonObject;
            } else {
                String token = JwtUtil.createJWT(6000000, user);
                jsonObject.put("token", token);
                jsonObject.put("user", user);
                return jsonObject;
            }
        }
    }

    //查看个人信息,验证jwt
    @CheckToken
    @GetMapping("/getMessage/{id}")
    public String getMessage(@PathVariable("id") String id) {
        User user = userMapper.selectByUserId(id);
        return "你已通过验证:"+user.getUserName();
    }

}
