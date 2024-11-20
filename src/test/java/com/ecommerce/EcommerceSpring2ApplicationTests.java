package com.ecommerce;

import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.containsStringIgnoringCase;
import static org.hamcrest.CoreMatchers.equalTo;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.Matchers.hasSize;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.net.URL;
import java.util.HashMap;
import java.util.Map;

import org.json.simple.JSONArray;
import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;
import org.junit.jupiter.api.Order;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestMethodOrder;
import org.junit.jupiter.api.MethodOrderer.OrderAnnotation;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.ecommerce.repository.CategoryRepository;
import com.ecommerce.repository.ProductRepository;
import com.ecommerce.repository.UserRepository;

@SpringBootTest
@RunWith(SpringRunner.class)
@TestMethodOrder(OrderAnnotation.class)
@AutoConfigureMockMvc
class EcommerceSpring2ApplicationTests {
	@Autowired
	MockMvc mvc;
	String cu = "jack", su = "apple", p = "pass_word";
	@Autowired
	CategoryRepository categoryRepo;
	@Autowired
	UserRepository userRepo;
	@Autowired
	ProductRepository productRepo;

	@Test
	@Order(4)
	public void productSearchStatus() throws Exception {
		mvc.perform(get("/api/public/product/search").param("keyword", "tablet")).andExpect(status().is(200))
				.andExpect(jsonPath("$", notNullValue()));
	}

	@Test
	@Order(5)
	public void productSearchWithoutKeyword() throws Exception {
		mvc.perform(get("/api/public/product/search")).andExpect(status().is(400));
	}

	@Test
	@Order(6)
	public void productSearchWithProductName() throws Exception {
		MvcResult res = mvc.perform(get("/api/public/product/search").param("keyword", "tablet"))
				.andExpect(status().is(200)).andReturn();
		JSONArray arr = (JSONArray) new JSONParser().parse(res.getResponse().getContentAsString());
		assert (arr.size() > 0);
		for (Object obj : arr) {
			assert (((JSONObject) obj).get("productName").toString().toLowerCase().contains("tablet"));
		}
	}

	@Test
	@Order(7)
	public void productSearchWithCategoryName() throws Exception {
		MvcResult res = mvc.perform(get("/api/public/product/search").param("keyword", "medicines"))
				.andExpect(status().is(200)).andReturn();
		JSONArray arr = (JSONArray) new JSONParser().parse(res.getResponse().getContentAsString());
		assert (arr.size() > 0);
		for (Object obj : arr) {
			assert (((JSONObject) ((JSONObject) obj).get("category")).get("categoryName").toString().toLowerCase()
					.contains("medicines"));
		}
	}

	@Test
	@Order(8)
	public void consumerAuthEndpoint() throws Exception {
		mvc.perform(get("/api/auth/consumer/cart")).andExpect(status().is(401));
	}

	@Test
	@Order(9)
	public void sellerAuthEndpoint() throws Exception {
		mvc.perform(get("/api/auth/seller/product")).andExpect(status().is(401));
	}

	@Test
	@Order(10)
	public void consumerLoginWithBadCreds() throws Exception {
		mvc.perform(
				post("/api/public/login").contentType(MediaType.APPLICATION_JSON).content(getJSONCreds(cu, "password")))
				.andExpect(status().is(401));
	}

	public String getJSONCreds(String u, String p) {
		Map<String, String> map = new HashMap<String, String>();
		map.put("username", u);
		map.put("password", p);
		JSONObject jsonObj = new JSONObject();
		jsonObj.putAll(map);
		return jsonObj.toJSONString();
	}

	public MockHttpServletResponse loginHelper(String u, String p) throws Exception {
		return mvc
				.perform(post("/api/public/login").contentType(MediaType.APPLICATION_JSON).content(getJSONCreds(u, p)))
				.andReturn().getResponse();
	}

	@Test
	@Order(11)
	public void consumerLoginwithValidCreds() throws Exception {
		assertEquals(200, loginHelper(cu, p).getStatus());
		assertNotEquals("", loginHelper(cu, p).getContentAsString());
	}

	@Test
	@Order(12)
	public void consumerGetCartWithValidJWT() throws Exception {
		String jwt = loginHelper(cu, p).getContentAsString();

		System.out.println("JWT TOKEN" + jwt);
		mvc.perform(get("/api/auth/consumer/cart").header("Authorization", "Bearer " + jwt)).andExpect(status().is(200))
				.andExpect(jsonPath("$.cartId", is(not(equalTo("")))))
				.andExpect(jsonPath("$.cartProducts[0].quantity", is(2)))
				.andExpect(jsonPath("$.cartProducts[0].product.productName",
						containsStringIgnoringCase("Crocin pain relief tablet")))
				.andExpect(jsonPath("$.cartProducts[0].product.category.categoryName", is("Medicines")));
	}

	@Test
	@Order(13)
	public void sellerApiWithConsumerJWT() throws Exception {
		mvc.perform(get("/api/auth/seller/product").header("Authorization",
				"Bearer " + loginHelper(cu, p).getContentAsString())).andExpect(status().is(403));
	}

	@Test
	@Order(14)
	public void sellerLoginWithValidCreds() throws Exception {
		assertEquals(200, loginHelper(su, p).getStatus());
		assertNotEquals("", loginHelper(su, p).getContentAsString());
	}

	@Test
	@Order(15)
	public void sellerGetProductsWithValidJWT() throws Exception {
		mvc.perform(get("/api/auth/seller/product").header("Authorization",
				"Bearer " + loginHelper(su, p).getContentAsString())).andExpect(status().is(200))
				.andExpect(jsonPath("$.[0].productId", is(not(equalTo("")))))
				.andExpect(jsonPath("$.[0].productName",
						containsStringIgnoringCase("Apple iPad 10.2 8th Gen WiFi 10S Tablet")))
				.andExpect(jsonPath("$.[0].category.categoryName", is("Electronics")));
	}

	@Test
	@Order(16)
	public void consumerApiWithSellerJWT() throws Exception {
		mvc.perform(get("/api/auth/consumer/cart").header("Authorization",
				"Bearer " + loginHelper(su, p).getContentAsString())).andExpect(status().is(403));
	}

	public JSONObject getProduct(int id, String name, Double price, int cId, String cName) {
		Map<String, String> mapC = new HashMap<String, String>();
		System.out.println("kartavya ::: " + id);
		mapC.put("categoryId", String.valueOf(cId));
		mapC.put("categoryName", cName);

		Map<String, Object> map = new HashMap<String, Object>();

		map.put("productId", id);
		map.put("productName", name);

		map.put("price", String.valueOf(price));

		map.put("category", mapC);
		JSONObject jsonObj = new JSONObject();
		jsonObj.putAll(map);
		return jsonObj;
	}

	static String createdURI;

	@Test
	@Order(17)
	public void sellerAddNewProduct() throws Exception {
		createdURI = mvc
				.perform(post("/api/auth/seller/product")
						.header("Authorization", "Bearer " + loginHelper(su, p).getContentAsString())
						.contentType(MediaType.APPLICATION_JSON)
						.content(getProduct(3, "IPhone 11", 49000.0, 2, "Electronics").toJSONString()))
				.andExpect(status().is(201)).andReturn().getResponse().getRedirectedUrl();
	}

	@SuppressWarnings("deprecation")
	@Test
	@Order(18)
	public void sellerCheckAddedNewProduct() throws Exception {
		System.out.println("sellerCheckAddedNewProduct ++ " + createdURI);
		mvc.perform(get(new URL(createdURI).getPath()).header("Authorization",
				"Bearer " + loginHelper(su, p).getContentAsString())).andExpect(status().is(200))
				.andExpect(jsonPath("$.productId", is(3))).andExpect(jsonPath("$.price", is(49000.0)))
				.andExpect(jsonPath("$.productName", is("IPhone 11")))
				.andExpect(jsonPath("$.category.categoryName", is("Electronics")));
		mvc.perform(get("/api/auth/seller/product").header("Authorization",
				"Bearer " + loginHelper(su, p).getContentAsString())).andExpect(status().is(200))
				.andExpect(content().string(containsString("IPhone 11")));
	}

	@SuppressWarnings("deprecation")
	@Test
	@Order(19)
	public void sellerCheckProductFromAnotherSeller() throws Exception {
		mvc.perform(get(new URL(createdURI).getPath()).header("Authorization",
				"Bearer " + loginHelper("glaxo", p).getContentAsString())).andExpect(status().is(404));
		mvc.perform(get("/api/auth/seller/product").header("Authorization",
				"Bearer " + loginHelper("glaxo", p).getContentAsString())).andExpect(status().is(200))
				.andExpect(content().string(not(containsString("IPhone 11"))));
	}

	@SuppressWarnings("deprecation")
	@Test
	@Order(20)
	public void sellerUpdateProduct() throws Exception {
		String[] arr = createdURI.split("/");
		mvc.perform(put("/api/auth/seller/product")
				.header("Authorization", "Bearer " + loginHelper(su, p).getContentAsString())
				.contentType(MediaType.APPLICATION_JSON)
				.content(getProduct(Integer.valueOf(arr[arr.length - 1]), "iPhone 12", 98888.0, 2, "Electronics")
						.toJSONString()))
				.andExpect(status().is(200));
		mvc.perform(get(new URL(createdURI).getPath()).header("Authorization",
				"Bearer " + loginHelper(su, p).getContentAsString())).andExpect(status().is(200))
				.andExpect(jsonPath("$.productId", is(Integer.valueOf(arr[arr.length - 1]))))
				.andExpect(jsonPath("$.productName", is("iPhone 12"))).andExpect(jsonPath("$.price", is(98888.0)))
				.andExpect(jsonPath("$.category.categoryName", is("Electronics")));
		mvc.perform(get("/api/auth/seller/product").header("Authorization",
				"Bearer " + loginHelper(su, p).getContentAsString())).andExpect(status().is(200))
				.andExpect(content().string(containsString("iPhone 12")));
	}

	@Test
	@Order(21)
	public void sellerUpdateProductWithWrongProductId() throws Exception {
		mvc.perform(put("/api/auth/seller/product")
				.header("Authorization", "Bearer " + loginHelper(su, p).getContentAsString())
				.contentType(MediaType.APPLICATION_JSON)
				.content(getProduct(55, "iPhone 12", 98008.0, 2, "Electronics").toJSONString()))
				.andExpect(status().is(404));
	}

	@Test
	@Order(22)
	public void consumerAddProductToCart() throws Exception {
		String[] arr = createdURI.split("/");
		System.out.println("createdURI :: " + createdURI);

		mvc.perform(get("/api/auth/consumer/cart").header("Authorization",
				"Bearer " + loginHelper(cu, p).getContentAsString()))
				.andExpect(content().string(not(containsString("iPhone 12"))));
		mvc.perform(post("/api/auth/consumer/cart")
				.header("Authorization", "Bearer " + loginHelper(cu, p).getContentAsString())
				.contentType(MediaType.APPLICATION_JSON)
				.content(getProduct(Integer.valueOf(arr[arr.length - 1]), "iPhone 12", 98800.8, 2, "Electronics")
						.toJSONString()))
				.andExpect(status().is(200));
		mvc.perform(get("/api/auth/consumer/cart").header("Authorization",
				"Bearer " + loginHelper(cu, p).getContentAsString()))
				.andExpect(content().string(containsString("iPhone 12")));
	}

	@Test
	@Order(23)
	public void consumerAddProductToCartAgain() throws Exception {
		String[] arr = createdURI.split("/");
		mvc.perform(post("/api/auth/consumer/cart")
				.header("Authorization", "Bearer " + loginHelper(cu, p).getContentAsString())
				.contentType(MediaType.APPLICATION_JSON)
				.content(getProduct(Integer.valueOf(arr[arr.length - 1]), "iPhone 12", 98000.0, 2, "Electronics")
						.toJSONString()))
				.andExpect(status().is(409));

	}

	public JSONObject getCartProduct(JSONObject product, int q) {
		Map<String, Object> map = new HashMap<String, Object>();
		map.put("product", product);
		map.put("quantity", q);
		JSONObject jsonObj = new JSONObject();
		jsonObj.putAll(map);
		return jsonObj;
	}

	@Test
	@Order(24)
	public void consumerUpdateProductInCart() throws Exception {
		String[] arr = createdURI.split("/");
		mvc.perform(put("/api/auth/consumer/cart")
				.header("Authorization", "Bearer " + loginHelper(cu, p).getContentAsString())
				.contentType(MediaType.APPLICATION_JSON)
				.content(getCartProduct(
						getProduct(Integer.valueOf(arr[arr.length - 1]), "iPhone 12", 98000.0, 2, "Electronics"), 3)
						.toJSONString()))
				.andExpect(status().is(200));
		mvc.perform(get("/api/auth/consumer/cart").header("Authorization",
				"Bearer " + loginHelper(cu, p).getContentAsString())).andExpect(status().is(200))
				.andExpect(jsonPath("$.cartId", is(not(equalTo("")))))
				.andExpect(jsonPath("$.cartProducts[1].quantity", is(3)))
				.andExpect(jsonPath("$.cartProducts[1].product.productName", containsStringIgnoringCase("iphone 12")))
				.andExpect(jsonPath("$.cartProducts[1].product.category.categoryName", is("Electronics")));
	}

	@Test
	@Order(25)
	public void consumerUpdateProductInCartWithZeroQuantity() throws Exception {
		String[] arr = createdURI.split("/");

		mvc.perform(put("/api/auth/consumer/cart")
				.header("Authorization", "Bearer " + loginHelper(cu, p).getContentAsString())
				.contentType(MediaType.APPLICATION_JSON)
				.content(getCartProduct(
						getProduct(Integer.valueOf(arr[arr.length - 1]), "iPhone 12", 98000.8, 2, "Electronics"), 0)
						.toJSONString()))
				.andExpect(status().is(200));

		mvc.perform(get("/api/auth/consumer/cart").header("Authorization",
				"Bearer " + loginHelper(cu, p).getContentAsString())).andExpect(status().is(200))
				.andExpect(jsonPath("$.cartId", is(not(equalTo(""))))).andExpect(jsonPath("$.cartProducts", hasSize(1)))
				.andExpect(jsonPath("$.cartProducts[0].quantity", is(2)))
				.andExpect(jsonPath("$.cartProducts[0].product.productName",
						containsStringIgnoringCase("Crocin pain relief tablet")))
				.andExpect(jsonPath("$.cartProducts[0].product.category.categoryName", is("Medicines")));
	}

	@Test
	@Order(26)
	public void consumerDeleteProductInCart() throws Exception {
		System.out.println(
				"jsonString :: " + getProduct(2, "Crocin pain relief tablet", 10.0, 5, "Medicines").toJSONString());
		mvc.perform(delete("/api/auth/consumer/cart")
				.header("Authorization", "Bearer " + loginHelper(cu, p).getContentAsString())
				.contentType(MediaType.APPLICATION_JSON)
				.content(getProduct(2, "Crocin pain relief tablet", 10.0, 5, "Medicines").toJSONString()))
				.andExpect(status().is(200)); // (int id, String name, Double price, int cId, String cName)

		mvc.perform(get("/api/auth/consumer/cart").header("Authorization",
				"Bearer " + loginHelper(cu, p).getContentAsString())).andExpect(status().is(200))
				.andExpect(jsonPath("$.cartId", is(not(equalTo("")))))
				.andExpect(jsonPath("$.cartProducts", hasSize(0)));

	}

	@Test
	@Order(27)
	public void sellerDeleteProduct() throws Exception {
		String[] arr = createdURI.split("/");
		mvc.perform(delete("/api/auth/seller/product/" + Integer.valueOf(arr[arr.length - 1])).header("Authorization",
				"Bearer " + loginHelper(su, p).getContentAsString())).andExpect(status().is(200));
		mvc.perform(get("/api/auth/seller/product/" + Integer.valueOf(arr[arr.length - 1])).header("Authorization",
				"Bearer " + loginHelper(su, p).getContentAsString())).andExpect(status().is(404));

	}

}
