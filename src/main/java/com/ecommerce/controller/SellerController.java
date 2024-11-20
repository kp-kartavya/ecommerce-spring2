package com.ecommerce.controller;

import java.net.URI;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ecommerce.config.JwtTokenProvider;
import com.ecommerce.models.CartProduct;
import com.ecommerce.models.Category;
import com.ecommerce.models.Product;
import com.ecommerce.models.User;
import com.ecommerce.repository.CartProductRepository;
import com.ecommerce.repository.CartRepository;
import com.ecommerce.repository.CategoryRepository;
import com.ecommerce.repository.ProductRepository;
import com.ecommerce.repository.UserRepository;

@RestController
@RequestMapping("/api/auth/seller/")
public class SellerController {
	@Autowired
	private CartRepository cartRepo;
	@Autowired
	private CategoryRepository categoryRepo;
	@Autowired
	private CartProductRepository cpRepo;
	@Autowired
	private UserRepository userRepo;
	@Autowired
	private ProductRepository productRepo;
	@Autowired
	private JwtTokenProvider jwtToken;

	@PostMapping("product")
	public ResponseEntity<Object> postProduct(@RequestHeader("Authorization") String jwt,
			@RequestBody Product product) {
		String username = extractUsernameBasedonJwtToken(jwt);
		User user = userRepo.findByUsername(username).orElse(null);
		if (user == null) {
			return ResponseEntity.badRequest().body("No User Found");
		}
		Category category = categoryRepo.findByCategoryName(product.getCategory().getCategoryName()).get();
		if (category == null) {
			return ResponseEntity.badRequest().body("No Category Found");
		}
		product.setSeller(user);
		product.setCategory(category);
		productRepo.saveAndFlush(product);
		HttpHeaders headers = new HttpHeaders();
		headers.setLocation(URI.create("http://localhost/api/auth/seller/product/" + product.getProductId()));
		return new ResponseEntity<>(headers, HttpStatus.CREATED);
	}

	@GetMapping("/product")
	public ResponseEntity<Object> getAllProducts(@RequestHeader("Authorization") String jwt) {
		String username = extractUsernameBasedonJwtToken(jwt);
		User user = userRepo.findByUsername(username).orElse(null);
		if (user == null) {
			return ResponseEntity.badRequest().body("No user found");
		}
		List<Product> list = productRepo.findBySellerUserId(user.getUserId());
		return ResponseEntity.ok(list);
	}

	@GetMapping("/product/{productId}")
	public ResponseEntity<Object> getProduct(@RequestHeader("Authorization") String jwt,
			@PathVariable(value = "productId") Integer productId) {
		String username = extractUsernameBasedonJwtToken(jwt);
		User user = userRepo.findByUsername(username).orElse(null);
		if (user == null) {
			return ResponseEntity.badRequest().body("No user found");
		}
		Product prod = productRepo.findBySellerUserIdAndProductId(user.getUserId(), productId).orElse(null);
		if (prod == null) {
			return ResponseEntity.status(404).body(null);
		}
		return ResponseEntity.ok(prod);
	}

	@PutMapping("/product")
	public ResponseEntity<Object> putProduct(@RequestHeader("Authorization") String jwt, @RequestBody Product product) {
		String username = extractUsernameBasedonJwtToken(jwt);
		User user = userRepo.findByUsername(username).orElse(null);
		if (user == null) {
			return ResponseEntity.badRequest().body("No user found");
		}
		Product prod = productRepo.findBySellerUserIdAndProductId(user.getUserId(), product.getProductId())
				.orElse(null);
		Category category = categoryRepo.findByCategoryName(product.getCategory().getCategoryName()).get();
		if (prod == null) {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No product found");
		}
		if (category == null) {
			return ResponseEntity.badRequest().body("No Category found");
		}
		prod.setProductName(product.getProductName());
		prod.setPrice(product.getPrice());
		prod.setCategory(category);
		productRepo.saveAndFlush(prod);
		return ResponseEntity.ok(prod);
	}

	@DeleteMapping("/product/{productId}")
	public ResponseEntity<Object> deleteProduct(@RequestHeader("Authorization") String jwt,
			@PathVariable(value = "productId") Integer productId) {
		String username = extractUsernameBasedonJwtToken(jwt);
		User user = userRepo.findByUsername(username).orElse(null);
		if (user == null) {
			return ResponseEntity.badRequest().body("User not found");
		}

		Product product = productRepo.findBySellerUserIdAndProductId(user.getUserId(), productId).orElse(null);
		if (product == null) {
			return ResponseEntity.status(404).body("Product not found");
		}

		// Delete related CartProduct entries first
		List<CartProduct> cartProducts = cpRepo.findAllByProductProductId(productId);
		cpRepo.deleteAll(cartProducts);

		productRepo.delete(product);
		return ResponseEntity.ok("Product deleted successfully");
	}

	public String extractUsernameBasedonJwtToken(String jwt) {
		String username = null;
		if (jwt != null && jwt.startsWith("Bearer")) {
			String token = jwt.substring(7);
			username = jwtToken.extractUsername(token);
		}
		return username;
	}
}
