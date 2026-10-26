package com.secufusion.oidcpoc;

import java.util.TimeZone;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class GoogleOidcPocApplication {
    public static void main(String[] args) {
        // PgJDBC sends the JVM time zone to Postgres, and current postgres images reject the legacy
        // name "Asia/Calcutta" ("invalid value for parameter TimeZone"). Pin UTC for any launcher,
        // including an IDE run configuration.
        TimeZone.setDefault(TimeZone.getTimeZone("UTC"));
        SpringApplication.run(GoogleOidcPocApplication.class, args);
    }
}
