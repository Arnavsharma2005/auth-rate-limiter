-- Uses up one refresh token, atomically.
-- KEYS[1] = refresh:<hash>        the token, value = session id
-- KEYS[2] = refresh-used:<hash>   remembers a used token, value = session id
-- ARGV[1] = how long to remember a used token, in milliseconds
-- Returns {sessionId, userId}, or an empty list if the token is unknown, expired, already used, or its session has ended.

local sessionId = redis.call('GETDEL', KEYS[1])
if not sessionId then
  -- A used token came back. Either the client or an attacker holds a copy, and we can't tell which,
  -- so the whole session ends: the token issued in its place stops working too.
  local reusedSession = redis.call('GET', KEYS[2])
  if reusedSession then
    redis.call('DEL', 'session:' .. reusedSession)
  end
  return {}
end

redis.call('SET', KEYS[2], sessionId, 'PX', ARGV[1])
local userId = redis.call('GET', 'session:' .. sessionId)
if not userId then
  return {}
end
return {sessionId, userId}
