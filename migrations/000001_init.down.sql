-- Stage 1: reverse initial schema

BEGIN;

DROP TABLE IF EXISTS review_queue;
DROP TABLE IF EXISTS whitelist_addresses;
DROP TABLE IF EXISTS policy_decisions;
DROP TABLE IF EXISTS policy_versions;
DROP TABLE IF EXISTS policies;

COMMIT;