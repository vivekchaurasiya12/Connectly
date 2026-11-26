-- Connectly Auth DB
-- DBD v1.0, Revision 1 — Sections 3.3, 7.2 and 7.3

CREATE TABLE account (
    account_id       UUID         PRIMARY KEY,
    user_id          UUID         NOT NULL,
    login_identifier VARCHAR(320) NOT NULL,
    account_status   VARCHAR(20)  NOT NULL,
    created_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at       TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_account_user_id UNIQUE (user_id),
    CONSTRAINT uq_account_login_identifier UNIQUE (login_identifier),
    CONSTRAINT chk_account_status
        CHECK (account_status IN ('ACTIVE', 'DISABLED'))
);

CREATE TABLE password_credential (
    credential_id UUID        PRIMARY KEY,
    account_id    UUID        NOT NULL,
    password_hash TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_password_credential_account_id UNIQUE (account_id),
    CONSTRAINT fk_password_credential_account
        FOREIGN KEY (account_id)
        REFERENCES account (account_id)
);

-- Shared timestamp function. updated_at is database-managed on INSERT and UPDATE.
CREATE OR REPLACE FUNCTION set_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.updated_at := CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_account_set_updated_at
BEFORE INSERT OR UPDATE ON account
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TRIGGER trg_password_credential_set_updated_at
BEFORE INSERT OR UPDATE ON password_credential
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

-- account_id and user_id are immutable after account creation.
CREATE OR REPLACE FUNCTION prevent_account_identity_change()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.account_id IS DISTINCT FROM OLD.account_id
       OR NEW.user_id IS DISTINCT FROM OLD.user_id THEN
        RAISE EXCEPTION 'account_id and user_id are immutable'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_account_identity_immutable
BEFORE UPDATE OF account_id, user_id ON account
FOR EACH ROW
EXECUTE FUNCTION prevent_account_identity_change();

-- Deferred exactly-one-credential invariant.
-- This allows account and password_credential to be inserted in one transaction.
CREATE OR REPLACE FUNCTION assert_account_has_exactly_one_credential(
    p_account_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_count BIGINT;
BEGIN
    IF p_account_id IS NULL THEN
        RETURN;
    END IF;

    -- If the account no longer exists, there is no remaining account invariant to check.
    IF NOT EXISTS (
        SELECT 1 FROM account WHERE account_id = p_account_id
    ) THEN
        RETURN;
    END IF;

    SELECT COUNT(*)
      INTO v_count
      FROM password_credential
     WHERE account_id = p_account_id;

    IF v_count <> 1 THEN
        RAISE EXCEPTION
            'Account % must have exactly one password credential; found %',
            p_account_id, v_count
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION check_account_credential_deferred()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'account' THEN
        PERFORM assert_account_has_exactly_one_credential(NEW.account_id);
    ELSE
        IF TG_OP <> 'INSERT' THEN
            PERFORM assert_account_has_exactly_one_credential(OLD.account_id);
        END IF;

        IF TG_OP <> 'DELETE' THEN
            PERFORM assert_account_has_exactly_one_credential(NEW.account_id);
        END IF;
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_account_exactly_one_credential
AFTER INSERT OR UPDATE ON account
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION check_account_credential_deferred();

CREATE CONSTRAINT TRIGGER trg_password_credential_exactly_one
AFTER INSERT OR UPDATE OR DELETE ON password_credential
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION check_account_credential_deferred();
