package com.egemen.userservice.controller;

import com.egemen.userservice.dto.AuthRequest;
import com.egemen.userservice.dto.AuthResponse;
import com.egemen.userservice.dto.RegisterRequest;
import com.egemen.userservice.dto.UserDto;
import com.egemen.userservice.model.Role;
import com.egemen.userservice.model.User;
import com.egemen.userservice.repository.RoleRepository;
import com.egemen.userservice.repository.UserRepository;
import com.egemen.userservice.security.CustomUserDetailsService;
import com.egemen.userservice.security.JwtService;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.List;
import java.util.Optional;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private RoleRepository roleRepository;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    @PostMapping("/login")
    public AuthResponse login(@RequestBody AuthRequest request) {
        System.out.println("Login denemesi: " + request.getUsername() + " / " + request.getPassword());

        Authentication auth = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        List<String> roles = auth.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        org.springframework.security.core.userdetails.UserDetails userDetails =
                (org.springframework.security.core.userdetails.UserDetails) auth.getPrincipal();

        String token = jwtService.generateToken(userDetails);

        return new AuthResponse(token, roles);
    }

    @PostMapping("/register")
    public AuthResponse register(@RequestBody RegisterRequest req) {
        if (userRepository.findByUsername(req.getUsername()).isPresent()) {
            throw new RuntimeException("Bu kullanıcı adı zaten mevcut!");
        }
        User user = new User();
        user.setUsername(req.getUsername());
        user.setPassword(passwordEncoder.encode(req.getPassword()));

        Role userRole = roleRepository.findByName("ROLE_USER")
                .orElseThrow(() -> new RuntimeException("ROLE_USER bulunamadı"));
        user.getRoles().add(userRole);
        userRepository.save(user);

        UserDetails ud = customUserDetailsService
                .loadUserByUsername(req.getUsername());

        String token = jwtService.generateToken(ud);
        List<String> roles = ud.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .toList();

        return new AuthResponse(token, roles);
    }


    @GetMapping("/me")
    public ResponseEntity<UserDto> getProfile() {
        Optional<User> userOpt = customUserDetailsService.getCurrentUser();

        if (userOpt.isEmpty()) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }

        User user = userOpt.get();
        List<String> roles = user.getRoles().stream()
                .map(Role::getName)
                .toList();

        UserDto userDto = new UserDto(user.getUsername(), roles);
        return ResponseEntity.ok(userDto);
    }


}
