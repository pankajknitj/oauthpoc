-- Insert into users table
INSERT INTO users (username, password, enabled) VALUES
    ('pankaj', '{noop}password', TRUE),
    ('anjali', '{bcrypt}$2a$12$8t3MCTsNaV3wgcEXP2cnc.M2PcuXsxZBgxybggY6W98h5gpufkXXW', FALSE);

-- Insert into authorities table
INSERT INTO authorities (username, authority) VALUES
    ('pankaj', 'read'),
    ('anjali', 'admin');

-- Insert into customer table
INSERT INTO customer (email, pwd, role) VALUES
    ('pankaj@example.com', '{noop}password', 'ACCOUNT_READ,LOANS_READ,BALANCE_READ'),
    ('anjali@example.com', '{bcrypt}$2a$12$8t3MCTsNaV3wgcEXP2cnc.M2PcuXsxZBgxybggY6W98h5gpufkXXW', 'CARDS_READ,');
