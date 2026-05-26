package com.admin.controller;


import com.admin.common.aop.LogAnnotation;
import com.admin.common.lang.R;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.admin.common.utils.PasswordUtil;
import com.admin.entity.User;
import com.admin.entity.UserTunnel;
import com.alibaba.fastjson2.JSONObject;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.web.bind.annotation.*;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/open_api")
public class OpenApiController extends BaseController {

    @LogAnnotation
    @PostMapping("/sub_store")
    public Object create(
            @RequestBody(required = false) Map<String, String> body,
            @RequestParam(value = "tunnel", required = false, defaultValue = "-1") String tunnel,
            HttpServletRequest request,
            HttpServletResponse response) {
        JSONObject result = new JSONObject();
        result.put("upload", 0);
        result.put("download", 0);
        result.put("total", 0);
        result.put("expire", 0);

        Credentials credentials = readCredentials(body, request);
        if (credentials.user == null || credentials.user.isEmpty()) {
            return R.err("用户不能为空");
        }
        if (credentials.password == null || credentials.password.isEmpty()) {
            return R.err("密码不能为空");
        }

        User userInfo = userService.getOne(new QueryWrapper<User>().eq("user", credentials.user));
        if (userInfo == null || !PasswordUtil.matches(credentials.password, userInfo.getPwd())) {
            return R.err("鉴权失败");
        }

        final long GIGA = 1024L * 1024L * 1024L;
        String headerValue;

        if ("-1".equals(tunnel)) {
            headerValue = buildSubscriptionHeader(
                    userInfo.getOutFlow(),
                    userInfo.getInFlow(),
                    userInfo.getFlow() * GIGA,
                    userInfo.getExpTime() / 1000
            );
        } else {
            UserTunnel tunnelInfo = userTunnelService.getById(tunnel);
            if (tunnelInfo == null) return R.err("隧道不存在");
            if (!tunnelInfo.getUserId().toString().equals(userInfo.getId().toString())) return R.err("隧道不存在");
            headerValue = buildSubscriptionHeader(
                    tunnelInfo.getOutFlow(),
                    tunnelInfo.getInFlow(),
                    tunnelInfo.getFlow() * GIGA,
                    tunnelInfo.getExpTime() / 1000
            );
        }

        response.setHeader("subscription-userinfo", headerValue);
        return headerValue;
    }


    private Credentials readCredentials(Map<String, String> body, HttpServletRequest request) {
        Credentials credentials = new Credentials();
        if (body != null) {
            credentials.user = body.get("user");
            credentials.password = body.get("pwd");
            if (credentials.password == null) credentials.password = body.get("password");
        }
        String authorization = request.getHeader("Authorization");
        if ((credentials.user == null || credentials.password == null) && authorization != null && authorization.startsWith("Basic ")) {
            try {
                String decoded = new String(Base64.getDecoder().decode(authorization.substring(6)), StandardCharsets.UTF_8);
                int idx = decoded.indexOf(':');
                if (idx > 0) {
                    credentials.user = decoded.substring(0, idx);
                    credentials.password = decoded.substring(idx + 1);
                }
            } catch (Exception ignored) {
            }
        }
        return credentials;
    }

    private static class Credentials {
        String user;
        String password;
    }

    private String buildSubscriptionHeader(long upload, long download, long total, long expire) {
        return String.format("upload=%d; download=%d; total=%d; expire=%d", download, upload, total, expire);
    }


}
