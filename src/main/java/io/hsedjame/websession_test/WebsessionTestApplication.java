package io.hsedjame.websession_test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.servlet.server.Session;
import org.springframework.context.annotation.Bean;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerAdapter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.session.MapSession;
import org.springframework.session.ReactiveMapSessionRepository;
import org.springframework.session.ReactiveSessionRepository;
import org.springframework.session.config.annotation.web.server.EnableSpringWebSession;
import org.springframework.session.data.redis.ReactiveRedisSessionRepository;
import org.springframework.session.data.redis.config.annotation.web.server.EnableRedisWebSession;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.server.session.HeaderWebSessionIdResolver;
import reactor.core.publisher.Mono;

import javax.script.ScriptEngine;
import java.util.Collections;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
@EnableSpringWebSession
public class WebsessionTestApplication {

    public static void main(String[] args) {
        SpringApplication.run(WebsessionTestApplication.class, args);
    }
}

@EnableRedisWebSession
class RedisConfig {

    @Bean
    public LettuceConnectionFactory redisConnectionFactory() {
        return new LettuceConnectionFactory();
    }

    //@Bean
    HeaderWebSessionIdResolver headerWebSessionIdResolver() {
        final HeaderWebSessionIdResolver resolver = new HeaderWebSessionIdResolver();
        resolver.setHeaderName("CURRENT_SESSION");
        return resolver;
    }
}

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
class WebFluxSecurityConfig {

   /* @Autowired
    private ReactiveAuthenticationManager authenticationManager;*/
    @Autowired
    private ServerSecurityContextRepository securityContextRepository;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf().disable()
                //.cors().configurationSource(SecurityUtils.corsConfigSource())
                // .and()
                .formLogin().disable()
                //.authenticationManager(authenticationManager)
                .securityContextRepository(securityContextRepository)
                .authorizeExchange()
                .pathMatchers(HttpMethod.OPTIONS).permitAll()
                .pathMatchers("/login/**").permitAll()
                .anyExchange().authenticated()
                .and().build();
    }

}

/*@Component
class MyAuthenticationmanager implements ReactiveAuthenticationManager {

    static ThreadLocal<ConcurrentHashMap<String, String>> credentials;

    static {
        credentials = new ThreadLocal<>();
        credentials.set(new ConcurrentHashMap<>());
        credentials.get().put("admin", "admin");
        credentials.get().put("user", "user");
    }
    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {

        final String password = authentication.getCredentials().toString();
        if (password != null) {
            final UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(password, password);
            return Mono.just(auth);
        } else return Mono.error(new Exception("Bad credentials."));

    }
}*/

@Component
class MySecurityContextRepository implements ServerSecurityContextRepository {

   /* @Autowired
    private ReactiveAuthenticationManager authenticationManager;
*/
    @Override
    public Mono<Void> save(ServerWebExchange swe, SecurityContext sc) {

        return swe.getSession().doOnNext(
                session -> {
                    if (sc != null) {
                        final String key = sc.getAuthentication().getCredentials().toString();
                        session.getAttributes().putIfAbsent(key, sc);
                    } else {
                        final String authHeader = getToken(swe);
                        session.getAttributes().remove(authHeader);
                    }

                }
        ).flatMap(WebSession::changeSessionId);

    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange swe) {

        final String authHeader = getToken(swe);

        if (authHeader != null)
            return swe.getSession()
                    .flatMap(session -> {
                        final SecurityContext sc = (SecurityContext) session.getAttribute(authHeader);
                        return Optional.ofNullable(sc).map(Mono::just).orElse(Mono.error(new Exception("Consider to login before.")));
                    })
                    /*.switchIfEmpty(Mono.defer(() -> {
                        final UsernamePasswordAuthenticationToken auth =
                                new UsernamePasswordAuthenticationToken(authHeader, authHeader,
                                        Collections.singletonList(new SimpleGrantedAuthority("ADMIN")));
                        return this.authenticationManager.authenticate(auth).map(SecurityContextImpl::new);
                    }))*/;

        return Mono.empty();
    }

    private String getToken(ServerWebExchange swe) {
        ServerHttpRequest request = swe.getRequest();
        return request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);
    }
}
