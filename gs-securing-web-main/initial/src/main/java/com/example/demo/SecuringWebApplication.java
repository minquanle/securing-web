// java
package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@SpringBootApplication(scanBasePackages = { "com.example.demo", "com.example.securingweb" })
@EnableJpaRepositories(basePackages = "com.example.demo.user")
@EntityScan(basePackages = "com.example.demo.user")
public class SecuringWebApplication {
    public static void main(String[] args) {
        SpringApplication.run(SecuringWebApplication.class, args);
    }
}
