package com.ecommerce.models;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.CascadeType;
import javax.persistence.Entity;
import javax.persistence.FetchType;
import javax.persistence.GeneratedValue;
import javax.persistence.GenerationType;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@Entity
public class Cart {
	@Id
	@GeneratedValue(strategy = GenerationType.IDENTITY)
	private Integer cartId;
	private Double totalAmount = 1.0;
	@OneToMany(fetch = FetchType.EAGER, mappedBy = "cart")
	@JsonIgnoreProperties("cart")
	private List<CartProduct> cartProducts = new ArrayList<>();
	@OneToOne(fetch = FetchType.EAGER, cascade = CascadeType.REMOVE)
	@JsonIgnore
	private User user;

	public void updateAmount(Double price) {
		this.totalAmount += price;
	}

	public Cart(Integer cartId, Double totalAmount, List<CartProduct> cartProducts, User user) {
		super();
		this.cartId = cartId;
		this.totalAmount = totalAmount;
		this.cartProducts = cartProducts;
		this.user = user;
	}

	public Cart() {
		super();
		// TODO Auto-generated constructor stub
	}

	public Integer getCartId() {
		return cartId;
	}

	public void setCartId(Integer cartId) {
		this.cartId = cartId;
	}

	public Double getTotalAmount() {
		return totalAmount;
	}

	public void setTotalAmount(Double totalAmount) {
		this.totalAmount = totalAmount;
	}

	public List<CartProduct> getCartProducts() {
		return cartProducts;
	}

	public void setCartProducts(List<CartProduct> cartProducts) {
		this.cartProducts = cartProducts;
	}

	public User getUser() {
		return user;
	}

	public void setUser(User user) {
		this.user = user;
	}
	
	
}
