package com.ecommerce.repository;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ecommerce.models.Product;

public interface ProductRepository extends JpaRepository<Product, Integer>{
	Optional<Product> findByProductName(String productName);
	List<Product> findByProductNameContainingIgnoreCaseOrCategoryCategoryNameContainingIgnoreCase(String productName, String categoryName);
	List<Product> findBySellerUserId(Integer userId);
	Optional<Product> findBySellerUserIdAndProductId(Integer userId, Integer productId);
}
