package com.task.api_gateway.infrastructure.filter;

import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@NullMarked
@Component
public class UserLoginHeaderFilter implements GlobalFilter, Ordered {

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
            .flatMap(context -> Mono.justOrEmpty(context.getAuthentication()))
            .filter(JwtAuthenticationToken.class::isInstance)
            .cast(JwtAuthenticationToken.class)
            .flatMap(auth -> Mono.justOrEmpty(auth.getToken().getClaimAsString("preferred_username")))
            .map(login -> mutate(exchange, login))
            .switchIfEmpty(Mono.fromSupplier(() -> mutate(exchange, null)))
            .flatMap(chain::filter);
    }

    private ServerWebExchange mutate(ServerWebExchange exchange, @Nullable String login) {
        return exchange.mutate().request(req -> req.headers(header -> {
            header.remove("X-User-Login");
            if (login != null) {
                header.set("X-User-Login", login);
            }
        })).build();
    }

    @Override
    public int getOrder() {
        return 0;
    }
}
