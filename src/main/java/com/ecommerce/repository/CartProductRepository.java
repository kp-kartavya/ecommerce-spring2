package com.ecommerce.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ecommerce.models.CartProduct;

public interface CartProductRepository extends JpaRepository<CartProduct, Integer> {
	List<CartProduct> findAllByProductProductId(Integer productId);
}
