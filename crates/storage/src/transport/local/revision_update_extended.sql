-- Variant of `memory_revision_update` for libraries that carry the legacy
-- content columns `when_to_use` / `superseded_by`.
--
-- Only the UPDATE trigger is defined here: the base `revision_schema.sql` still
-- installs the insert/delete triggers and the meta seed, and this file replaces
-- that one trigger afterwards. It is selected purely by column presence (see
-- `revision::refresh_update_trigger`), because a library created by the current
-- schema does not have these columns at all and a WHEN branch naming a missing
-- column makes `CREATE TRIGGER` fail — which would break every new library on
-- first open.
CREATE TRIGGER IF NOT EXISTS memory_revision_update AFTER UPDATE ON memories
WHEN OLD.id IS NOT NEW.id
  OR OLD.user IS NOT NEW.user
  OR OLD.ciphertext IS NOT NEW.ciphertext
  OR OLD.nonce IS NOT NEW.nonce
  OR OLD.updated_at IS NOT NEW.updated_at
  OR OLD.deleted IS NOT NEW.deleted
  OR OLD.kind IS NOT NEW.kind
  OR OLD.tags IS NOT NEW.tags
  OR OLD.title IS NOT NEW.title
  OR OLD.project IS NOT NEW.project
  OR OLD.computer IS NOT NEW.computer
  OR OLD.created_at IS NOT NEW.created_at
  OR OLD.parent_id IS NOT NEW.parent_id
  OR OLD.content_head IS NOT NEW.content_head
  OR OLD.importance IS NOT NEW.importance
  OR OLD.device IS NOT NEW.device
  OR OLD.modified_by IS NOT NEW.modified_by
  -- Legacy content columns: present only on libraries upgraded from a release
  -- that carried them. A change here is still new memory content.
  OR OLD.when_to_use IS NOT NEW.when_to_use
  OR OLD.superseded_by IS NOT NEW.superseded_by
BEGIN
    UPDATE meta SET value = lower(hex(randomblob(16))) WHERE key = 'memory_revision_v1';
END;
