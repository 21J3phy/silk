-- Apply once using a separate, approved migration authority. Never the runtime
-- role. No credentials, LOGIN roles, owner identities or grants are provisioned.
BEGIN;
CREATE SCHEMA silk_mailbox;
REVOKE ALL ON SCHEMA silk_mailbox FROM PUBLIC;

CREATE TABLE silk_mailbox.agents (
    agent_id text COLLATE "C" PRIMARY KEY CHECK (agent_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{7,99}$'),
    owner_id text COLLATE "C" NOT NULL CHECK (owner_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{7,99}$'),
    display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 100 AND octet_length(display_name)<=400),
    disabled_at bigint,
    lock_version bigint NOT NULL DEFAULT 0
);
CREATE TABLE silk_mailbox.agent_bindings (
    issuer text COLLATE "C" NOT NULL CHECK (char_length(issuer) BETWEEN 1 AND 2048),
    subject text COLLATE "C" NOT NULL CHECK (char_length(subject) BETWEEN 1 AND 2048),
    client_id text COLLATE "C" NOT NULL CHECK (char_length(client_id) BETWEEN 1 AND 2048),
    agent_id text COLLATE "C" NOT NULL REFERENCES silk_mailbox.agents(agent_id),
    created_at bigint NOT NULL CHECK (created_at>=0),
    expires_at bigint NOT NULL CHECK (expires_at>created_at),
    revoked_at bigint,
    lock_version bigint NOT NULL DEFAULT 0,
    PRIMARY KEY (issuer,subject,client_id)
);
CREATE TABLE silk_mailbox.pair_quotas (
    pair_id text COLLATE "C" PRIMARY KEY CHECK (pair_id ~ '^[0-9a-f]{64}$'),
    agent_a text COLLATE "C" NOT NULL REFERENCES silk_mailbox.agents(agent_id),
    agent_b text COLLATE "C" NOT NULL REFERENCES silk_mailbox.agents(agent_id),
    lock_version bigint NOT NULL DEFAULT 0,
    UNIQUE (agent_a,agent_b), UNIQUE(pair_id,agent_a,agent_b),
    CHECK (agent_a<agent_b)
);
CREATE TABLE silk_mailbox.pair_grants (
    grant_id text COLLATE "C" PRIMARY KEY CHECK (grant_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{7,99}$'),
    pair_id text COLLATE "C" NOT NULL,
    agent_a text COLLATE "C" NOT NULL,
    agent_b text COLLATE "C" NOT NULL,
    scope text NOT NULL CHECK (scope='message.coordinate'),
    created_at bigint NOT NULL CHECK (created_at>=0),
    expires_at bigint NOT NULL CHECK (expires_at>created_at),
    revoked_at bigint,
    max_turns integer NOT NULL CHECK (max_turns BETWEEN 1 AND 32),
    used_turns integer NOT NULL DEFAULT 0 CHECK (used_turns BETWEEN 0 AND max_turns),
    max_ttl integer NOT NULL CHECK (max_ttl BETWEEN 1 AND 300),
    -- Opaque references to separately obtained consent evidence, not copies of
    -- private conversations. These cannot be populated from a JWT alone.
    consent_a_reference text NOT NULL CHECK (char_length(consent_a_reference) BETWEEN 1 AND 200 AND consent_a_reference NOT LIKE 'fixture-only:%'),
    consent_b_reference text NOT NULL CHECK (char_length(consent_b_reference) BETWEEN 1 AND 200 AND consent_b_reference NOT LIKE 'fixture-only:%'),
    UNIQUE(grant_id,pair_id),
    FOREIGN KEY(pair_id,agent_a,agent_b) REFERENCES silk_mailbox.pair_quotas(pair_id,agent_a,agent_b),
    CHECK(agent_a<agent_b)
);
CREATE TABLE silk_mailbox.messages (
    message_id text COLLATE "C" PRIMARY KEY CHECK (message_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{7,99}$'),
    grant_id text COLLATE "C" NOT NULL,
    pair_id text COLLATE "C" NOT NULL,
    sender_agent_id text COLLATE "C" NOT NULL REFERENCES silk_mailbox.agents(agent_id),
    recipient_agent_id text COLLATE "C" NOT NULL REFERENCES silk_mailbox.agents(agent_id),
    text text CHECK (text IS NULL OR (char_length(text) BETWEEN 1 AND 2000 AND octet_length(text)<=4096)),
    created_at bigint NOT NULL CHECK(created_at>=0),
    expires_at bigint NOT NULL CHECK(expires_at>created_at AND expires_at<=created_at+300),
    idempotency_key text COLLATE "C" NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{7,99}$'),
    intent_digest text NOT NULL CHECK(intent_digest ~ '^[0-9a-f]{64}$'),
    reply_to text COLLATE "C" REFERENCES silk_mailbox.messages(message_id),
    UNIQUE(sender_agent_id,idempotency_key),
    UNIQUE(message_id,sender_agent_id,recipient_agent_id),
    FOREIGN KEY(grant_id,pair_id) REFERENCES silk_mailbox.pair_grants(grant_id,pair_id),
    CHECK(sender_agent_id<>recipient_agent_id)
);
CREATE TABLE silk_mailbox.receipts (
    receipt_id text COLLATE "C" PRIMARY KEY CHECK (receipt_id ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{7,99}$'),
    message_id text COLLATE "C" NOT NULL UNIQUE,
    sender_agent_id text COLLATE "C" NOT NULL,
    recipient_agent_id text COLLATE "C" NOT NULL,
    outcome text NOT NULL CHECK(outcome IN ('received','declined')),
    recorded_at bigint NOT NULL CHECK(recorded_at>=0),
    -- Original admitted message-intent digest. Not a signature.
    request_digest text NOT NULL CHECK(request_digest ~ '^[0-9a-f]{64}$'),
    -- Internal digest of message_id + recipient decision for ACK replay.
    acknowledgment_digest text NOT NULL CHECK(acknowledgment_digest ~ '^[0-9a-f]{64}$'),
    idempotency_key text COLLATE "C" NOT NULL CHECK(idempotency_key ~ '^[A-Za-z0-9][A-Za-z0-9_.:-]{7,99}$'),
    UNIQUE(recipient_agent_id,idempotency_key),
    FOREIGN KEY(message_id,sender_agent_id,recipient_agent_id) REFERENCES silk_mailbox.messages(message_id,sender_agent_id,recipient_agent_id)
);
CREATE TABLE silk_mailbox.mailbox_limits (
    singleton integer PRIMARY KEY CHECK(singleton=1),
    max_messages bigint NOT NULL CHECK(max_messages BETWEEN 1 AND 10000000),
    max_receipts bigint NOT NULL CHECK(max_receipts BETWEEN 1 AND 10000000),
    max_agents bigint NOT NULL CHECK(max_agents BETWEEN 1 AND 100000),
    max_bindings bigint NOT NULL CHECK(max_bindings BETWEEN 1 AND 100000),
    max_grants bigint NOT NULL CHECK(max_grants BETWEEN 1 AND 100000),
    lock_version bigint NOT NULL DEFAULT 0
);
-- Conservative starting ceilings, not a provider/cost authorization. The
-- operator must explicitly choose lower/higher ceilings before real use.
INSERT INTO silk_mailbox.mailbox_limits VALUES(1,100000,100000,10000,20000,10000,0);
CREATE INDEX messages_pair_rate ON silk_mailbox.messages(pair_id,created_at);
CREATE INDEX messages_recipient ON silk_mailbox.messages(recipient_agent_id,expires_at);
CREATE INDEX messages_content_expiry ON silk_mailbox.messages(expires_at) WHERE text IS NOT NULL;
CREATE INDEX messages_grant ON silk_mailbox.messages(grant_id);
CREATE INDEX receipts_sender ON silk_mailbox.receipts(sender_agent_id,recorded_at);
CREATE INDEX receipts_recipient ON silk_mailbox.receipts(recipient_agent_id,recorded_at);
CREATE INDEX grants_agent_a ON silk_mailbox.pair_grants(agent_a,expires_at);
CREATE INDEX grants_agent_b ON silk_mailbox.pair_grants(agent_b,expires_at);
REVOKE ALL ON ALL TABLES IN SCHEMA silk_mailbox FROM PUBLIC;
COMMIT;
