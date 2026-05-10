USE KEYDB;

CREATE TABLE KEYS_LIST (
    id INT AUTO_INCREMENT PRIMARY KEY,
    `public_key` TEXT NOT NULL,
    `private_key` TEXT NOT NULL,
    `machine_id` VARCHAR(255) NOT NULL,
    `content` MEDIUMTEXT
);