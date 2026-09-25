-- Guard recovery requires persisted ownership of the exact account revision.
-- Any other writer's updated_at revokes this ownership automatically.
CREATE TABLE IF NOT EXISTS account_token_guard_ownership (
    account_id BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    account_updated_at TIMESTAMPTZ NOT NULL
);
