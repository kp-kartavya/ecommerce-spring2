package com.ecommerce.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.ecommerce.models.Category;

public interface CategoryRepository extends JpaRepository<Category, Integer>{
	Optional<Category> findByCategoryName(String categoryName);
}
