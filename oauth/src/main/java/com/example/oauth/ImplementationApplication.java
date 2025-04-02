package com.example.oauth;

import io.github.cdimascio.dotenv.Dotenv;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.info.Contact;
import io.swagger.v3.oas.annotations.info.Info;
import org.springframework.cache.annotation.EnableCaching;
import java.nio.file.Paths;

@OpenAPIDefinition(
		info = @Info(
				title = "User Registrations API",
				description = "Simple user register and login service",
				version = "v1.0",
				contact = @Contact(
						name = "Asmit Gurung",
						email = "gurung@gmail.com"
				)
		)
)
@SpringBootApplication
@EnableCaching
public class ImplementationApplication {

	public static void main(String[] args) {
		Dotenv dotenv = Dotenv.configure()
				.directory(Paths.get("C:\\Users\\Asus\\Downloads\\oauth\\oauth").toAbsolutePath().toString())
				.ignoreIfMissing()
				.load();

		// Database configuration
		System.setProperty("spring.datasource.url", dotenv.get("SPRING_DATASOURCE_URL"));
		System.setProperty("spring.datasource.username", dotenv.get("SPRING_DATASOURCE_USERNAME"));
		System.setProperty("spring.datasource.password", dotenv.get("SPRING_DATASOURCE_PASSWORD"));

		// OAuth configuration (CRITICAL MISSING PART)
		System.setProperty("spring.security.oauth2.client.registration.google.client-id", dotenv.get("GOOGLE_CLIENT_ID"));
		System.setProperty("spring.security.oauth2.client.registration.google.client-secret", dotenv.get("GOOGLE_CLIENT_SECRET"));
		System.setProperty("spring.security.oauth2.client.registration.google.redirect-uri", dotenv.get("GOOGLE_REDIRECT_URI"));

		// Email configuration
		System.setProperty("spring.mail.host", dotenv.get("MAIL_HOST"));
		System.setProperty("spring.mail.port", dotenv.get("MAIL_PORT"));
		System.setProperty("spring.mail.username", dotenv.get("MAIL_USERNAME"));
		System.setProperty("spring.mail.password", dotenv.get("MAIL_PASSWORD"));

		// Profile configuration
		System.setProperty("spring.profiles.active", dotenv.get("SPRING_PROFILES_ACTIVE", "dev"));

		SpringApplication.run(ImplementationApplication.class, args);
	}
}


