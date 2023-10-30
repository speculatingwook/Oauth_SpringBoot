package com.speculatingwook.OauthSpringBoot;

import com.speculatingwook.OauthSpringBoot.global.config.properties.AppProperties;
import com.speculatingwook.OauthSpringBoot.global.config.properties.CorsProperties;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties({
		CorsProperties.class,
		AppProperties.class
})
public class OauthSpringBootApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthSpringBootApplication.class, args);
	}

}