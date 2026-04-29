-- quota.lua
-- Daily scan quota enforcement script for FastAPI Gateway
--
-- This Lua script is executed by Redis via the EVAL command.
-- It implements a sliding daily quota counter per API key or user.
--
-- Usage:
--   redis.eval(lua_script, keys={quota_key}, args={ttl_seconds, daily_limit})
--
-- Keys:
--   KEYS[1] - Redis key for the quota counter (e.g., "quota:api_key_123:2025-04-14")
--
-- Arguments:
--   ARGV[1] - TTL in seconds for the key (e.g., 86400 for 24 hours)
--   ARGV[2] - Daily request limit (integer)
--
-- Returns:
--   {current_count, quota_exceeded}
--     current_count     - The current number of requests made today
--     quota_exceeded    - 0 if within quota, 1 if quota exceeded
--
-- Example:
--   local result = redis.call("EVAL", quota_lua, 1, "quota:user123:2025-04-14", 86400, 1000)
--   -- result = {42, 0}  => 42 requests made, still within quota

local current = redis.call("INCR", KEYS[1])
if current == 1 then
  redis.call("EXPIRE", KEYS[1], ARGV[1])
end

if current > tonumber(ARGV[2]) then
  return {current, 1}
end

return {current, 0}
