package com.ecommerce.controller;

import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.ecommerce.config.JwtTokenProvider;
import com.ecommerce.models.JwtRequest;
import com.ecommerce.models.Product;
import com.ecommerce.repository.ProductRepository;
import com.ecommerce.repository.UserRepository;

@CrossOrigin(origins = "http://localhost:3000")
@RestController
@RequestMapping("/api/public/")
public class PublicController {
	private static final Logger logger = LogManager.getLogger(PublicController.class);
	@Autowired
	AuthenticationManager auth;
	@Autowired
	JwtTokenProvider jwtToken;
	@Autowired
	ProductRepository productRepo;
	@Autowired
	UserRepository userRepo;

	@GetMapping("product/search")
	public List<Product> getCart(@RequestParam String keyword) {
		return productRepo.findByProductNameContainingIgnoreCaseOrCategoryCategoryNameContainingIgnoreCase(keyword,
				keyword);
	}

	@PostMapping("login")
	public ResponseEntity<String> login(@RequestBody JwtRequest request) {
		try {
			auth.authenticate(
					new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));
			return ResponseEntity.ok(jwtToken.generateToken(request.getUsername()));
		} catch (Exception e) {
			return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Authentication failed");
		}
	}
}
