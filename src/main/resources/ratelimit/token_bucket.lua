-- Token bucket. Redis runs the whole script atomically, so concurrent requests can't both take the last token.
-- KEYS[1] = bucket key
-- ARGV[1] = capacity (max tokens)
-- ARGV[2] = refill rate in tokens per millisecond
-- ARGV[3] = current time in milliseconds
-- ARGV[4] = key expiry in milliseconds
-- Returns {allowed (1/0), milliseconds until one token is available (0 if allowed)}

local key = KEYS[1]
local capacity = tonumber(ARGV[1])
local rate = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])

local state = redis.call('HMGET', key, 'tokens', 'ts')
local tokens = tonumber(state[1])
local ts = tonumber(state[2])
if tokens == nil then
  tokens = capacity
  ts = now
end

-- Add the tokens earned since the last request, but never more than capacity
local elapsed = math.max(0, now - ts)
tokens = math.min(capacity, tokens + elapsed * rate)

local allowed = 0
local wait_ms = 0
if tokens >= 1 then
  tokens = tokens - 1
  allowed = 1
else
  wait_ms = math.ceil((1 - tokens) / rate)
end

-- Fractional tokens are kept as strings so partial refills aren't lost
redis.call('HSET', key, 'tokens', tostring(tokens), 'ts', tostring(now))
redis.call('PEXPIRE', key, ttl)
return {allowed, wait_ms}
