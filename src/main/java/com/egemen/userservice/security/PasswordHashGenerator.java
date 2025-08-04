package com.egemen.userservice.security;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
public class PasswordHashGenerator {
    public static void main(String[] args) {
        BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
        String hashed = encoder.encode("123456");
        System.out.println("Encoded password: " + hashed);
    }}
