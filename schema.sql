CREATE TABLE IF NOT EXISTS "User" (
    IdUser INTEGER PRIMARY KEY,
    UserName VARCHAR(255) NOT NULL UNIQUE CHECK(length(UserName) <= 255),
    Password VARCHAR(255) NOT NULL CHECK(length(Password) <= 255),
    Token VARCHAR(255) CHECK(Token IS NULL OR length(Token) <= 255)
);
