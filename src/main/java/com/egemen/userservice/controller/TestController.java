package com.egemen.userservice.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/test")
public class TestController {
/*
    @GetMapping("/secured")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<String> securedEndpoint() {
        return ResponseEntity.ok("✅ Bu endpoint'e JWT ile başarıyla erişildi.");
    }
    */

    @GetMapping("/secured")
    public ResponseEntity<String> testSecured() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        System.out.println("Auth: " + auth);
        return ResponseEntity.ok("Token geldi, kullanıcı: " + auth.getName());
    }
}
