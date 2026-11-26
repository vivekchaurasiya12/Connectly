-- Connectly Auth DB
-- DBD v1.0, Revision 1 — Sections 7.9, 10.19, 10.20 and 11.6

CREATE TABLE auth_outbox_event (
    outbox_event_id   UUID         PRIMARY KEY,
    event_id          UUID         NOT NULL,
    event_type        VARCHAR(100) NOT NULL,
    aggregate_type    VARCHAR(100) NOT NULL,
    aggregate_id      UUID         NOT NULL,
    payload           JSONB        NOT NULL,
    publication_status VARCHAR(20) NOT NULL,
    attempt_count     INTEGER      NOT NULL,
    next_attempt_at   TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    claim_token       UUID         NULL,
    claimed_at        TIMESTAMPTZ  NULL,
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    published_at      TIMESTAMPTZ  NULL,

    CONSTRAINT uq_auth_outbox_event_id UNIQUE (event_id),

    CONSTRAINT chk_auth_outbox_publication_status
        CHECK (publication_status IN ('PENDING', 'PUBLISHING', 'PUBLISHED')),

    CONSTRAINT chk_auth_outbox_attempt_count
        CHECK (attempt_count >= 0),

    CONSTRAINT chk_auth_outbox_claim_consistency
        CHECK (
            (
                publication_status = 'PUBLISHING'
                AND claim_token IS NOT NULL
                AND claimed_at IS NOT NULL
            )
            OR
            (
                publication_status <> 'PUBLISHING'
                AND claim_token IS NULL
                AND claimed_at IS NULL
            )
        ),

    CONSTRAINT chk_auth_outbox_published_consistency
        CHECK (
            (
                publication_status = 'PUBLISHED'
                AND published_at IS NOT NULL
            )
            OR
            (
                publication_status <> 'PUBLISHED'
                AND published_at IS NULL
            )
        )
);

-- Exact DBD polling and stale-claim recovery indexes.
CREATE INDEX idx_auth_outbox_pending_poll
    ON auth_outbox_event (
        next_attempt_at,
        created_at,
        outbox_event_id
    )
    WHERE publication_status = 'PENDING';

CREATE INDEX idx_auth_outbox_stale_claim
    ON auth_outbox_event (claimed_at)
    WHERE publication_status = 'PUBLISHING';
