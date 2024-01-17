package kea.dpang.gateway.component;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

@Component
public class L1Filter extends AbstractGatewayFilterFactory<L1Filter.Config> {

    public L1Filter(){
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return ((exchange, chain) -> {
            if (config.isPre()){
                // pre local filter
            }
            // pre 변수가 true 이면 실행

            return chain.filter(exchange)
                    .then(Mono.fromRunnable(()->{
                        if(config.isPost()){
                            // post local filter
                        }
                        // post 변수가 true 이면 실행
                    }));
        });
    }

    @NoArgsConstructor
    @AllArgsConstructor
    @Data
    public static class Config{
        private boolean pre;
        private boolean post;
    }
}
// 지역 필터
// 특정 마이크로 서비스가 지역 필터를 거친다.