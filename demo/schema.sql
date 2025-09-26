CREATE TABLE IF NOT EXISTS Users (
    id          INTEGER  PRIMARY KEY,
    username    TEXT     NOT NULL UNIQUE,
    hash        TEXT     NOT NULL,
    email       TEXT     NOT NULL UNIQUE,
    signup_time DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS Posts (
    id                  INTEGER  PRIMARY KEY,
    author              INTEGER  NOT NULL,
    title               TEXT     NOT NULL,
    is_link             BOOLEAN  NOT NULL,
    content             TEXT     NOT NULL,
    submit_time         DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author) REFERENCES Users(id)
);

CREATE TABLE IF NOT EXISTS Comments (
    id             INTEGER  PRIMARY KEY,
    parent_post    INTEGER  NOT NULL,
    parent_comment INTEGER,
    author         INTEGER  NOT NULL,
    content        TEXT     NOT NULL,
    submit_time    DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (author)         REFERENCES Users(id),
    FOREIGN KEY (parent_post)    REFERENCES Posts(id),
    FOREIGN KEY (parent_comment) REFERENCES Comments(id)
);
