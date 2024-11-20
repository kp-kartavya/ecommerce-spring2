package com.ecommerce.config;

import java.util.Date;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

@Component
public class JwtTokenProvider {
	private static final Logger logger = LogManager.getLogger(JwtTokenProvider.class);
	@Autowired
	private CustomUserDetailsService userDetailsService;
	@Value("${app.expiration}")
	private long jwtExpiration;

	public Claims extractClaims(String token) {
		return Jwts.parser().setSigningKey("secret").parseClaimsJws(token).getBody();
	}

	public String generateToken(String  username) {
		Date current = new Date();
		Date expired = new Date(current.getTime() + jwtExpiration);
		String token = Jwts.builder().setSubject(username).setIssuedAt(current).setExpiration(expired)
				.signWith(SignatureAlgorithm.HS256, "secret").compact();
		return token;
	}

	public String extractUsername(String token) {
		return extractClaims(token).getSubject();
	}

	public Date extractExpiration(String token) {
		return extractClaims(token).getExpiration();
	}

	public boolean validateToken(String token, UserDetails user) {
		return user.getUsername().equals(extractUsername(token)) && extractExpiration(token).after(new Date());
	}

}
