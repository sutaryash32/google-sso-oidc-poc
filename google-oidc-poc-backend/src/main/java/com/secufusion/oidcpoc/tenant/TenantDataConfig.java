package com.secufusion.oidcpoc.tenant;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import javax.sql.DataSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceTransactionManager;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

/**
 * Builds the application DataSource and transaction beans. Boot's JDBC auto-configuration is excluded
 * in application.yml so this is the single place the connection is configured.
 */
@Configuration
public class TenantDataConfig {

    @Bean(destroyMethod = "close")
    public DataSource tenantDataSource(TenantProperties props) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(props.datasource().url());
        config.setUsername(props.datasource().username());
        config.setPassword(props.datasource().password());
        config.setMaximumPoolSize(5);
        return new HikariDataSource(config);
    }

    @Bean
    public JdbcTemplate jdbcTemplate(DataSource tenantDataSource) {
        return new JdbcTemplate(tenantDataSource);
    }

    @Bean
    public PlatformTransactionManager transactionManager(DataSource tenantDataSource) {
        return new DataSourceTransactionManager(tenantDataSource);
    }

    @Bean
    public TransactionTemplate transactionTemplate(PlatformTransactionManager transactionManager) {
        return new TransactionTemplate(transactionManager);
    }
}
