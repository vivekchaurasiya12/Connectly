-- Connectly Auth DB
-- DBD v1.0, Revision 1 — Sections 7.5, 7.6 and 7.7

CREATE TABLE refresh_token_family (
    token_family_id   UUID        PRIMARY KEY,
    session_id        UUID        NOT NULL,
    current_generation BIGINT     NOT NULL,
    family_status     VARCHAR(20) NOT NULL,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT uq_refresh_token_family_session_id UNIQUE (session_id),

    CONSTRAINT fk_refresh_token_family_session
        FOREIGN KEY (session_id)
        REFERENCES auth_session (session_id),

    CONSTRAINT chk_refresh_token_family_status
        CHECK (family_status IN ('ACTIVE', 'REVOKED', 'EXPIRED')),

    CONSTRAINT chk_refresh_token_family_generation
        CHECK (current_generation >= 0)
);

CREATE TRIGGER trg_refresh_token_family_set_updated_at
BEFORE INSERT OR UPDATE ON refresh_token_family
FOR EACH ROW
EXECUTE FUNCTION set_updated_at();

CREATE TABLE refresh_token (
    refresh_token_id UUID        PRIMARY KEY,
    token_family_id  UUID        NOT NULL,
    generation       BIGINT      NOT NULL,
    token_hash       BYTEA       NOT NULL,
    token_status     VARCHAR(20) NOT NULL,
    expires_at       TIMESTAMPTZ NOT NULL,
    successor_token_id UUID      NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at          TIMESTAMPTZ NULL,

    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT uq_refresh_token_family_generation
        UNIQUE (token_family_id, generation),
    CONSTRAINT uq_refresh_token_family_token
        UNIQUE (token_family_id, refresh_token_id),

    CONSTRAINT fk_refresh_token_family
        FOREIGN KEY (token_family_id)
        REFERENCES refresh_token_family (token_family_id),

    CONSTRAINT fk_refresh_token_successor_same_family
        FOREIGN KEY (token_family_id, successor_token_id)
        REFERENCES refresh_token (token_family_id, refresh_token_id),

    CONSTRAINT chk_refresh_token_status
        CHECK (token_status IN ('ACTIVE', 'USED', 'EXPIRED', 'REVOKED')),

    CONSTRAINT chk_refresh_token_generation
        CHECK (generation >= 0),

    CONSTRAINT chk_refresh_token_expiry
        CHECK (expires_at > created_at),

    CONSTRAINT chk_refresh_token_successor_state
        CHECK (
            (token_status = 'ACTIVE' AND successor_token_id IS NULL)
            OR
            (token_status = 'USED' AND successor_token_id IS NOT NULL)
            OR
            (token_status IN ('EXPIRED', 'REVOKED'))
        )
);

-- DBD-defined partial unique indexes.
CREATE UNIQUE INDEX uq_refresh_token_active_family
    ON refresh_token (token_family_id)
    WHERE token_status = 'ACTIVE';

CREATE UNIQUE INDEX uq_refresh_token_successor
    ON refresh_token (successor_token_id)
    WHERE successor_token_id IS NOT NULL;

-- Validate successor generation, self-reference, and immutable successor assignment.
CREATE OR REPLACE FUNCTION validate_refresh_token_successor()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_successor_generation BIGINT;
    v_successor_family UUID;
    v_is_new_successor BOOLEAN := FALSE;
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.successor_token_id IS NOT NULL
       AND NEW.successor_token_id IS DISTINCT FROM OLD.successor_token_id THEN
        RAISE EXCEPTION 'An established successor relationship cannot be reassigned'
            USING ERRCODE = '23514';
    END IF;

    v_is_new_successor :=
        NEW.successor_token_id IS NOT NULL
        AND (
            TG_OP = 'INSERT'
            OR OLD.successor_token_id IS NULL
        );

    IF v_is_new_successor THEN
        -- A successor is assigned only as part of ACTIVE -> USED rotation.
        IF TG_OP = 'INSERT' OR OLD.token_status <> 'ACTIVE'
           OR NEW.token_status <> 'USED' THEN
            RAISE EXCEPTION
                'A new successor may only be assigned during ACTIVE to USED rotation'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF NEW.successor_token_id IS NOT NULL THEN
        IF NEW.successor_token_id = NEW.refresh_token_id THEN
            RAISE EXCEPTION 'A refresh token cannot be its own successor'
                USING ERRCODE = '23514';
        END IF;

        -- DBD: EXPIRED/REVOKED may retain a previously established successor,
        -- but cannot acquire a new one. USED -> REVOKED remains valid.
        IF NEW.token_status NOT IN ('USED', 'REVOKED', 'EXPIRED') THEN
            RAISE EXCEPTION
                'A token with a successor must remain USED, REVOKED, or EXPIRED'
                USING ERRCODE = '23514';
        END IF;

        SELECT token_family_id, generation
          INTO v_successor_family, v_successor_generation
          FROM refresh_token
         WHERE refresh_token_id = NEW.successor_token_id;

        IF NOT FOUND THEN
            RAISE EXCEPTION 'Successor token % does not exist', NEW.successor_token_id
                USING ERRCODE = '23503';
        END IF;

        IF v_successor_family <> NEW.token_family_id THEN
            RAISE EXCEPTION 'A successor must belong to the same token family'
                USING ERRCODE = '23514';
        END IF;

        IF v_successor_generation <> NEW.generation + 1 THEN
            RAISE EXCEPTION 'Successor generation must equal predecessor generation plus one'
                USING ERRCODE = '23514';
        END IF;
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_refresh_token_validate_successor
BEFORE INSERT OR UPDATE ON refresh_token
FOR EACH ROW
EXECUTE FUNCTION validate_refresh_token_successor();

-- Enforce the DBD token lifecycle and used_at rules.
CREATE OR REPLACE FUNCTION enforce_refresh_token_lifecycle()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.token_status IS DISTINCT FROM OLD.token_status THEN
        IF NOT (
            (OLD.token_status = 'ACTIVE'
                AND NEW.token_status IN ('USED', 'EXPIRED', 'REVOKED'))
            OR
            (OLD.token_status IN ('USED', 'EXPIRED')
                AND NEW.token_status = 'REVOKED')
        ) THEN
            RAISE EXCEPTION 'Invalid refresh-token status transition: % -> %',
                OLD.token_status, NEW.token_status
                USING ERRCODE = '23514';
        END IF;
    END IF;

    IF OLD.used_at IS NOT NULL
       AND NEW.used_at IS DISTINCT FROM OLD.used_at THEN
        RAISE EXCEPTION 'used_at is immutable after it is set'
            USING ERRCODE = '23514';
    END IF;

    IF OLD.token_status = 'ACTIVE' AND NEW.token_status = 'USED' THEN
        NEW.used_at := CURRENT_TIMESTAMP;
    ELSIF OLD.used_at IS NULL AND NEW.used_at IS NOT NULL THEN
        RAISE EXCEPTION 'used_at may only be set during ACTIVE to USED transition'
            USING ERRCODE = '23514';
    END IF;

    RETURN NEW;
END;
$$;

CREATE TRIGGER trg_refresh_token_lifecycle
BEFORE UPDATE ON refresh_token
FOR EACH ROW
EXECUTE FUNCTION enforce_refresh_token_lifecycle();

-- Deferred family consistency: validate the final state at transaction commit.
CREATE OR REPLACE FUNCTION assert_refresh_token_family_consistency(
    p_token_family_id UUID
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_family_status VARCHAR(20);
    v_current_generation BIGINT;
    v_active_count BIGINT;
    v_active_generation BIGINT;
BEGIN
    SELECT family_status, current_generation
      INTO v_family_status, v_current_generation
      FROM refresh_token_family
     WHERE token_family_id = p_token_family_id;

    IF NOT FOUND THEN
        RETURN;
    END IF;

    SELECT COUNT(*), MIN(generation)
      INTO v_active_count, v_active_generation
      FROM refresh_token
     WHERE token_family_id = p_token_family_id
       AND token_status = 'ACTIVE';

    IF v_family_status = 'ACTIVE' THEN
        IF v_active_count <> 1 THEN
            RAISE EXCEPTION
                'ACTIVE token family % must have exactly one ACTIVE token; found %',
                p_token_family_id, v_active_count
                USING ERRCODE = '23514';
        END IF;

        IF v_active_generation <> v_current_generation THEN
            RAISE EXCEPTION
                'ACTIVE token generation % must match family current_generation % for family %',
                v_active_generation, v_current_generation, p_token_family_id
                USING ERRCODE = '23514';
        END IF;
    ELSIF v_active_count <> 0 THEN
        RAISE EXCEPTION
            'Non-active token family % cannot contain an ACTIVE token',
            p_token_family_id
            USING ERRCODE = '23514';
    END IF;
END;
$$;

CREATE OR REPLACE FUNCTION check_refresh_token_family_consistency_deferred()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_TABLE_NAME = 'refresh_token_family' THEN
        -- Family identity is the primary key; validate the affected family.
        PERFORM assert_refresh_token_family_consistency(NEW.token_family_id);
    ELSE
        -- UPDATE may affect two families; DELETE has only OLD; INSERT has only NEW.
        IF TG_OP <> 'INSERT' THEN
            PERFORM assert_refresh_token_family_consistency(OLD.token_family_id);
        END IF;

        IF TG_OP <> 'DELETE' THEN
            PERFORM assert_refresh_token_family_consistency(NEW.token_family_id);
        END IF;
    END IF;

    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER trg_refresh_token_family_consistency
AFTER INSERT OR UPDATE ON refresh_token_family
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION check_refresh_token_family_consistency_deferred();

CREATE CONSTRAINT TRIGGER trg_refresh_token_consistency
AFTER INSERT OR UPDATE OR DELETE ON refresh_token
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION check_refresh_token_family_consistency_deferred();
