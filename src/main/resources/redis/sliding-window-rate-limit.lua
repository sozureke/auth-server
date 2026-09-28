-- Sliding-window-log rate limiter. One ZSET per key, one member per accepted request.
-- KEYS[1] = key
-- ARGV[1] = limit, ARGV[2] = window in ms, ARGV[3] = per-request nonce (keeps members unique)
-- Returns { allowed (1|0), remaining, resetMs }
-- resetMs = time until the oldest accepted request leaves the window, i.e. until a slot frees up.
-- Time comes from Redis (TIME), not the caller, so app instances with skewed clocks agree.
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

local t = redis.call('TIME')
local now = t[1] * 1000 + math.floor(t[2] / 1000)

redis.call('ZREMRANGEBYSCORE', KEYS[1], '-inf', now - window)
local count = redis.call('ZCARD', KEYS[1])

if count >= limit then
  local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
  return { 0, 0, math.ceil(tonumber(oldest[2]) + window - now) }
end

redis.call('ZADD', KEYS[1], now, now .. ':' .. ARGV[3])
redis.call('PEXPIRE', KEYS[1], window)

local oldest = redis.call('ZRANGE', KEYS[1], 0, 0, 'WITHSCORES')
return { 1, limit - count - 1, math.ceil(tonumber(oldest[2]) + window - now) }
