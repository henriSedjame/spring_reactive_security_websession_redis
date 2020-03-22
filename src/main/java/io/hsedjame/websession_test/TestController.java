package io.hsedjame.websession_test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;

import java.util.Arrays;
import java.util.Collections;
import java.util.Optional;

@RestController
public class TestController {
    @Autowired
    ServerSecurityContextRepository securityContextRepository;

    @GetMapping("/webSession")
    public Mono<String> getSession(WebSession session) {
        session.getAttributes().putIfAbsent("note", "Already is fine");
        return Mono.just((String) session.getAttribute("note"));
    }

    @GetMapping("/webSession2")
    public Mono<String> getSession2(ServerWebExchange swe) {
        return swe.getSession().doOnNext(session -> {
            session.getAttributes().putIfAbsent("note2", "Already is always fine");
        }).map(session -> Optional.ofNullable((String) session.getAttribute("note2")).orElse("Error"));
    }

    @PostMapping("/login/{username}/{password}")
    public Mono<Void> login(ServerWebExchange swe, @PathVariable String username, @PathVariable String password) {
        Authentication auth = new UsernamePasswordAuthenticationToken(username, password, Collections.singletonList(new SimpleGrantedAuthority("ADMIN")));
        return securityContextRepository.save(swe, new SecurityContextImpl(auth));
    }

    @GetMapping("/logout")
    public Mono<Void> logout(ServerWebExchange swe){
        return securityContextRepository.save(swe, null);
    }
}
