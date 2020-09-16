# TODO: change order of passurl and url

create_details_table = """
CREATE TABLE IF NOT EXISTS details (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  passUrl TEXT ,
  url TEXT NOT NULL,
  sitename TEXT NOT NULL,
  email TEXT NOT NULL,
  password TEXT NOT NULL
);
"""

create_user_table = """
CREATE TABLE IF NOT EXISTS user (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_pass TEXT NOT NULL
);
"""
insert_table_values = """
INSERT INTO details (url, passUrl, sitename, email, password)
VALUES (?,?,?,?,?)
"""

insert_user_pass_value = """
INSERT INTO user (user_pass) VALUES (?)
"""

select_user_pass_value = """
SELECT user_pass from user LIMIT 1
"""

retrieve_detail_data = """
SELECT * FROM details
"""

delete_james = """
DELETE FROM user WHERE user_pass='sam'
"""
