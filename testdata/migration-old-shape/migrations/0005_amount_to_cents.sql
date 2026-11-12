-- orders.amount (text) becomes orders.amount_cents (integer).
ALTER TABLE orders ADD COLUMN amount_cents INTEGER;
UPDATE orders SET amount_cents = CAST(amount AS INTEGER) * 100;
ALTER TABLE orders DROP COLUMN amount;
