package com.ecommerce.controller;

import java.util.ArrayList;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ecommerce.config.JwtTokenProvider;
import com.ecommerce.models.Cart;
import com.ecommerce.models.CartProduct;
import com.ecommerce.models.Product;
import com.ecommerce.models.User;
import com.ecommerce.repository.CartProductRepository;
import com.ecommerce.repository.CartRepository;
import com.ecommerce.repository.CategoryRepository;
import com.ecommerce.repository.ProductRepository;
import com.ecommerce.repository.UserRepository;

@RestController
@RequestMapping("/api/auth/consumer")
public class ConsumerController {
	private static final Logger logger = LogManager.getLogger(ConsumerController.class);
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

	@GetMapping("/cart")
	public ResponseEntity<Object> getCart(@RequestHeader("Authorization") String jwt) {
		logger.info("Inside getCart :: " + jwt);
		String username = extractUsernameBasedonJwtToken(jwt);
		logger.info("username getCart :: " + username);
		Cart cart = cartRepo.findByUserUsername(username).orElse(null);
		return ResponseEntity.ok(cart);
	}

	@PostMapping("/cart")
	public ResponseEntity<Object> postCart(@RequestHeader("Authorization") String jwt, @RequestBody Product product) {
		logger.info("POST /cart endpoint hit");
		logger.info("Received JWT: " + jwt);
		String username = extractUsernameBasedonJwtToken(jwt);
		logger.info("Extracted Username: " + username);

		Cart cart = cartRepo.findByUserUsername(username).orElse(null);
		if (cart == null) {
			logger.info("Cart not found for user: " + username);
			return ResponseEntity.status(404).body("Cart not found");
		}

		if (cart.getCartProducts() == null) {
			cart.setCartProducts(new ArrayList<>());
		}

		Product prod = productRepo.findById(product.getProductId()).orElse(null);
		if (prod == null) {
			logger.info("Product not found with ID: " + product.getProductId());
			return ResponseEntity.status(404).body("Product not found");
		}

		boolean productExistsInCart = cart.getCartProducts().stream().anyMatch(n -> n.getProduct().equals(prod));

		if (!productExistsInCart) {
			CartProduct cp = new CartProduct();
			cp.setCart(cart);
			cp.setProduct(prod);
			cp.setQuantity(1);
			cpRepo.save(cp); // Save CartProduct to generate cpId
			cart.getCartProducts().add(cp);
			cart.updateAmount(prod.getPrice() * cp.getQuantity());
			cartRepo.save(cart);
			logger.info("Product added to cart successfully");
			return ResponseEntity.ok(cart);
		} else {
			logger.info("Product already in cart");
			return ResponseEntity.status(409).body("Product already in cart");
		}
	}

	@PutMapping("/cart")
	public ResponseEntity<Object> putCart(@RequestHeader("Authorization") String jwt,
			@RequestBody CartProduct cartProd) {
		try {
			String username = extractUsernameBasedonJwtToken(jwt);
			User user = userRepo.findByUsername(username).orElse(null);
			if (user == null) {
				return ResponseEntity.badRequest().body("No User Found");
			}

			Cart cart = cartRepo.findByUserUsername(username).orElse(null);
			if (cart == null) {
				return ResponseEntity.badRequest().body("No Cart Found for User");
			}

			Product prod = productRepo.findById(cartProd.getProduct().getProductId()).orElse(null);
			if (prod == null) {
				return ResponseEntity.badRequest().body("No Product Found");
			}

			CartProduct cp = cart.getCartProducts().stream().filter(n -> n.getProduct().equals(prod)).findFirst()
					.orElse(null);

			if (cp == null) {
				if (cartProd.getQuantity() > 0) {
					cp = new CartProduct();
					prod.setProductName(cartProd.getProduct().getProductName());
					cp.setProduct(prod);
					cp.setQuantity(cartProd.getQuantity());
					cart.updateAmount(prod.getPrice() * cartProd.getQuantity());
					cp.setCart(cart);
					cart.getCartProducts().add(cp);
				}
			} else {
				if (cartProd.getQuantity() == 0) {
					cart.getCartProducts().remove(cp);
					cart.updateAmount(-prod.getPrice() * cp.getQuantity());
					cpRepo.delete(cp);
				} else {
					prod.setProductName(cartProd.getProduct().getProductName());
					cart.updateAmount(prod.getPrice() * (cartProd.getQuantity() - cp.getQuantity()));
					cp.setQuantity(cartProd.getQuantity());
				}
			}

			cartRepo.saveAndFlush(cart);
			return ResponseEntity.ok(cart);
		} catch (Exception e) {
			logger.error("Error updating cart: ", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
		}
	}

	@DeleteMapping("/cart")
	public ResponseEntity<Object> deleteCart(@RequestHeader("Authorization") String jwt, @RequestBody Product prod) {
		try {
			logger.info("INSIDE DELETE CART: ");
			String username = extractUsernameBasedonJwtToken(jwt);
			logger.info("Extracted Username: " + username);

			Cart cart = cartRepo.findByUserUsername(username).orElse(null);
			if (cart == null) {
				logger.info("Cart not found for user: " + username);
				return ResponseEntity.badRequest().body("No cart found for user");
			}

			CartProduct cp = cart.getCartProducts().stream().filter(n -> n.getProduct().getProductId().equals(prod.getProductId())).findFirst()
					.orElse(null);
			if (cp == null) {
				logger.info("Product not found in cart: " + prod.getProductId());
				return ResponseEntity.badRequest().body("No product found in cart");
			}

			cart.getCartProducts().remove(cp);
			cart.updateAmount(-cp.getProduct().getPrice() * cp.getQuantity());
			cpRepo.delete(cp);
			cartRepo.save(cart);

			logger.info("Product removed from cart successfully");
			return ResponseEntity.ok(cart);
		} catch (Exception e) {
			logger.error("Error deleting product from cart: ", e);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Internal server error");
		}
	}

	public String extractUsernameBasedonJwtToken(String jwt) {
		String username = null;
		System.out.println("extractUsernameBasedonJwtToken :: " + jwt);
		if (jwt != null && jwt.startsWith("Bearer")) {
			String token = jwt.substring(7);
			username = jwtToken.extractUsername(token);
		}
		return username;
	}
}
