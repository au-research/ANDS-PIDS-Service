CREATE SCHEMA `dbs_sequence`;


CREATE TABLE `dbs_sequence`.`sequence_data` (
    `sequence_name` varchar(100) NOT NULL,
    `sequence_increment` int(11) unsigned NOT NULL DEFAULT 1,
    `sequence_min_value` int(11) unsigned NOT NULL DEFAULT 1,
    `sequence_max_value` bigint(20) unsigned NOT NULL DEFAULT 18446744073709551615,
    `sequence_cur_value` bigint(20) unsigned DEFAULT 1,
    `sequence_cycle` boolean NOT NULL DEFAULT FALSE,
    PRIMARY KEY (`sequence_name`)
) ENGINE=InnoDB;


INSERT INTO dbs_sequence.sequence_data (sequence_name) VALUE ('handlesuffix_seq');

SET GLOBAL log_bin_trust_function_creators = 1;

DELIMITER $$

CREATE FUNCTION `nextval` (`seq_name` varchar(100))
RETURNS bigint(20) NOT DETERMINISTIC
BEGIN
    DECLARE cur_val bigint(20);

    SELECT
        `sequence_cur_value` INTO cur_val
    FROM
        `dbs_sequence`.`sequence_data`
    WHERE
        `sequence_name` = `seq_name`;

    IF cur_val IS NOT NULL THEN
        UPDATE
            `dbs_sequence`.`sequence_data`
        SET
            `sequence_cur_value` = IF (
                (`sequence_cur_value` + `sequence_increment`) > `sequence_max_value`,
                IF (
                    `sequence_cycle` = TRUE,
                    `sequence_min_value`,
                    NULL
                ),
                `sequence_cur_value` + `sequence_increment`
            )
        WHERE
            `sequence_name` = `seq_name`
        ;
    END IF;

    RETURN cur_val;
END$$

SET SQL_SAFE_UPDATES = 0;

CREATE SCHEMA `dbs_pids`;

use dbs_pids;

CREATE TABLE nas (
	`na` VARCHAR(255) NOT null,
	PRIMARY KEY(na)
) ENGINE=InnoDB;

CREATE TABLE handles (
	`handle` VARCHAR(255) NOT null,
	`idx` int4 not null,
	`type` blob,
	`data` blob,
	`ttl_type` int2,
	`ttl` int4,
	`timestamp` int4,
	`refs` blob,
	`admin_read` bool,
	`admin_write` bool,
	`pub_read` bool,
	`pub_write` bool,
	PRIMARY KEY(`handle`, `idx`)
) ENGINE=InnoDB;


CREATE INDEX handles_handle_idx on handles(handle);

CREATE TABLE trusted_client
(
    `ip_address`    VARCHAR(15),
    `app_id`        VARCHAR(40),
    `shared_secret` VARCHAR(15),
    `description`   VARCHAR(255),
    `created_when` timestamp DEFAULT now();
) ENGINE=InnoDB;

CREATE INDEX trusted_client_ip_address_idx ON trusted_client(ip_address);
CREATE INDEX trusted_client_appid_idx ON trusted_client(app_id);

CREATE OR REPLACE
VIEW `search_view` AS
    SELECT
        `handles`.`handle` AS `handle`,
        CONVERT( `handles`.`data` USING UTF8) AS `data`
    FROM
        `handles`
    WHERE
        ((`handles`.`type` = CAST('DESC' AS CHAR CHARSET BINARY))
            OR (`handles`.`type` = CAST('URL' AS CHAR CHARSET BINARY)))

            
CREATE USER 'piduser'@'localhost';
GRANT ALL ON `dbs_pids`.* TO 'piduser'@'localhost';