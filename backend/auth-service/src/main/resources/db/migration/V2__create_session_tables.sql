-- Connectly Auth DB
-- DBD v1.0, Revision 1 — Section 7.4

CREATE TABLE auth_session (
    session_id           UUID        PRIMARY KEY,
    account_id           UUID        NOT NULL,
    session_status       VARCHAR(20) NOT NULL,
    connection_generation BIGINT     NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at           TIMESTAMPTZ NOT NULL,
    revoked_at           TIMESTAMPTZ NULL,
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT fk_auth_session_account
        FOREIGN KEY (account_id)
        REFERENCES account (account_id),

    CONSTRAINT chk_auth_session_status
        CHECK (session_status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),

    CONSTRAINT chk_auth_session_connection_generation
        CHECK (connection_generation >= 0),

    CONSTRAINT chk_auth_session_expiry
        CHECK (expires_at > created_at)
);

CREATE TRIGGER trg_auth_session_set_updated_at
BEFORE INSERT OR UPDATE ON auth_session
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();
