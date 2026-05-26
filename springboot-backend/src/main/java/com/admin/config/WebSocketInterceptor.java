package com.admin.config;


import com.admin.common.utils.IpUtils;
import com.admin.common.utils.JwtUtil;
import com.admin.common.utils.NodeAuthUtil;
import com.admin.entity.Node;
import com.admin.service.NodeService;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.web.socket.WebSocketHandler;
import org.springframework.web.socket.server.support.HttpSessionHandshakeInterceptor;

import javax.annotation.Resource;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;


@Configuration
@Slf4j
public class WebSocketInterceptor extends HttpSessionHandshakeInterceptor {

    @Resource
    NodeService nodeService;

    @Override
    public void afterHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Exception ex) {

    }

    @Override
    public boolean beforeHandshake(ServerHttpRequest request, ServerHttpResponse response, WebSocketHandler wsHandler, Map<String, Object> attributes) throws Exception {
        ServletServerHttpRequest serverHttpRequest = (ServletServerHttpRequest) request;
        String secret = serverHttpRequest.getServletRequest().getParameter("secret");
        String type = serverHttpRequest.getServletRequest().getParameter("type");
        String version = serverHttpRequest.getServletRequest().getParameter("version");
        if (Objects.equals(type, "1")) {
            if (secret == null || secret.isBlank()) {
                secret = serverHttpRequest.getServletRequest().getHeader(NodeAuthUtil.HEADER_SECRET);
            }
            if (serverHttpRequest.getServletRequest().getParameter("secret") != null
                    && !Boolean.parseBoolean(System.getenv().getOrDefault("ALLOW_LEGACY_NODE_SECRET_QUERY", "false"))) {
                log.info("节点验证失败：拒绝 URL query 中传递 secret");
                return false;
            }
            log.info("节点 WebSocket 握手 - type: {} - version: {} - IP: {}", type, version, getClientIp(request));
            Node node = nodeService.getOne(new QueryWrapper<Node>().eq("secret", secret));
            if (node == null) {
                log.info("节点验证失败：未找到匹配的secret");
                return false;
            }
            attributes.put("id", node.getId());
            attributes.put("nodeSecret", secret);
            attributes.put("nodeVersion", version);
            log.info("节点 {} 通过验证，版本: {}", node.getId(), version);
            // 不在这里更新状态，等到连接建立后再统一更新
        }else {
            if (secret == null || secret.isBlank()) {
                secret = readTokenFromSubprotocol(serverHttpRequest);
            }
            if (serverHttpRequest.getServletRequest().getParameter("secret") != null
                    && !Boolean.parseBoolean(System.getenv().getOrDefault("ALLOW_LEGACY_WS_TOKEN_QUERY", "false"))) {
                log.info("用户 WebSocket 验证失败：拒绝 URL query 中传递 token");
                return false;
            }
            boolean b = JwtUtil.validateToken(secret);
            if (!b) return false;
            attributes.put("id", JwtUtil.getUserIdFromToken(secret));
        }
        attributes.put("type", type);
        return true;
    }
    private String readTokenFromSubprotocol(ServletServerHttpRequest request) {
        String protocols = request.getServletRequest().getHeader("Sec-WebSocket-Protocol");
        if (protocols == null) return null;
        for (String protocol : protocols.split(",")) {
            protocol = protocol.trim();
            if (protocol.startsWith("flux-jwt.")) {
                String encoded = protocol.substring("flux-jwt.".length()).replace('-', '+').replace('_', '/');
                while (encoded.length() % 4 != 0) encoded += "=";
                try {
                    return new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
                } catch (Exception ignored) {
                    return null;
                }
            }
        }
        return null;
    }

    public String getClientIp(ServerHttpRequest request) {
        InetSocketAddress remoteAddress = request.getRemoteAddress();
        if (remoteAddress != null) {
            return remoteAddress.getAddress().getHostAddress();
        }
        return null;
    }


}
