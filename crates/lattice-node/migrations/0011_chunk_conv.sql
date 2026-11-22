ALTER TABLE chunks_index ADD COLUMN IF NOT EXISTS conv_id text;
CREATE INDEX IF NOT EXISTS chunks_index_conv_idx ON chunks_index (conv_id);
