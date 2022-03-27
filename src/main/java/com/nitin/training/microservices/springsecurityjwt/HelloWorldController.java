package com.nitin.training.microservices.springsecurityjwt;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloWorldController {

	@GetMapping(value= "/hello")
	public String sayHelloWorld() {
		return "Hello World";
	}
}
