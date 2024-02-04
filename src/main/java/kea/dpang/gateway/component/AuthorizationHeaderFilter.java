package kea.dpang.gateway.component;

import io.jsonwebtoken.*;
import kea.dpang.gateway.Roles;
import kea.dpang.gateway.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Base64;
import java.util.List;

@Component
@Slf4j
public class AuthorizationHeaderFilter extends AbstractGatewayFilterFactory<AuthorizationHeaderFilter.Config> {

    private final JwtTokenProvider jwtTokenProvider;

    @Autowired
    public AuthorizationHeaderFilter(JwtTokenProvider jwtTokenProvider){
        super(Config.class);
        this.jwtTokenProvider = jwtTokenProvider;
    }

    public static class Config {

    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            ServerHttpRequest request = exchange.getRequest();
            log.info("AuthorizationHeaderFilter 시작: request -> {}", exchange.getRequest());

            HttpHeaders headers = request.getHeaders();
            if (!headers.containsKey(HttpHeaders.AUTHORIZATION)) {
                log.error("헤더에 Authorization이 포함되어 있지 않습니다. ");
                return onError(exchange, "No authorization header", HttpStatus.UNAUTHORIZED);
            }

            // JWT 토큰 판별
            String token = headers.get(HttpHeaders.AUTHORIZATION).get(0);

            if (token.startsWith("Bearer ")){
                token = token.substring(7);
            }
            else {
                log.error("올바른 토큰 형태가 아닙니다.(Bearer 부재)");
                return onError(exchange, "Bearer is missing", HttpStatus.UNAUTHORIZED);
            }

            jwtTokenProvider.validateJwtToken(token);
            log.info("토큰 유효성 통과 : Token -> {}",token);

            Long userId = jwtTokenProvider.getUserId(token);
            log.info("사용자 식별자: userId -> {}",userId);
            String roles = jwtTokenProvider.getRoles(token);
            log.info("사용자 권한: roles -> {}",roles);

            if (!roles.contains(Roles.ADMIN.toString())) {
                log.error("사용자 권한 없음: 사용자 권한 -> {}",roles);
                return onError(exchange, "권한 없음", HttpStatus.UNAUTHORIZED);
            }

            ServerHttpRequest newRequest = request.mutate()
                    .header("X-DPANG-CLIENT-ID", String.valueOf(userId))
                    .header("X-DPANG-ROLE", roles)
                    .build();
            log.info("Request에 header 추가: client-id -> {}, role -> {}", userId, roles);

            log.info("AuthorizationHeaderFilter 종료: newRequest -> {}",newRequest.getHeaders());
            return chain.filter(exchange.mutate().request(newRequest).build());
        };
    }

    // Mono(단일 값), Flux(다중 값) -> Spring WebFlux
    private Mono<Void> onError(ServerWebExchange exchange, String errorMsg, HttpStatus httpStatus) {
        log.error(errorMsg);

        ServerHttpResponse response = exchange.getResponse();
        response.setStatusCode(httpStatus);

        return response.setComplete();
    }
}
