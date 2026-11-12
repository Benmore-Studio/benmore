-- What the schema cannot say: a trigger and a reference row.
CREATE TRIGGER orders_log_insert AFTER INSERT ON orders BEGIN
  INSERT INTO order_events (user_id, order_id, kind) VALUES (NEW.user_id, NEW.id, 'created');
END;
INSERT INTO currencies (code, name) VALUES ('USD', 'US dollar');
