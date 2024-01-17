package kea.dpang.gateway.component;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class G1Filter implements GlobalFilter, Ordered {
    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // pre global filter
        // pre : 마이크로 서비스 실행 전 수행
        return chain.filter(exchange)
                .then(Mono.fromRunnable(()->{
                    // post global filter
                    // post : 마이크로 서비스 실행 후 수행
                }));
    }

    @Override
    public int getOrder() {
        return 0;
    }
    // 필터 순서값 지정
    // 번호가 작을수록 pre가 먼저 실행되고, post가 나중에 실행됨
}
// 글로벌 필터
// 모든 마이크로 서비스가 글로벌 필터를 거친다.