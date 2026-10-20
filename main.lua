--[[
    Readable reconstruction of the "MAWW" loader.

    The original was obfuscated with two layers:
      1. String encryption: every string went through g(bytes, n), a per-call XOR
         with key = KEY_TABLE[(n-1) % 16 + 1] XOR ((n*73 + 41) & 255).
      2. Control-flow flattening: every function body was a `while true do` state
         machine driven by a __cfN variable with opaque predicates such as
         bit32.bor(x, x) == x (always true). All of that is removed here and the
         real logic is restored in plain order.

    All variable names are renamed by hand. Behaviour is unchanged.
    Decrypted constants are marked with [decoded].
]]

----------------------------------------------------------------------
-- Config (all strings below are [decoded])
----------------------------------------------------------------------
local BASE_URL    = "https://free-mawwhub.vercel.app/api"
local AUTH_URL    = BASE_URL .. "/auth"
local LOAD_URL    = BASE_URL .. "/load"
local TAG_VALUE   = "maww-v1"            -- sent in header X-Maww-Tag
local MAX_RETRIES = 3
local RETRY_DELAY = 2

local HttpService = game:GetService("HttpService")
local Players     = game:GetService("Players")


----------------------------------------------------------------------
-- Pool of loadstring-like functions.
-- Registers syn.loadstring / loadstring / load under random keys and
-- returns a wrapper that picks one at random each call.
----------------------------------------------------------------------
local compile = (function()
    local registry = {}   -- randomKey -> function
    local keys     = {}   -- list of randomKeys
    local counter  = 0

    local ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" -- [decoded]

    local function register(fn)
        if type(fn) ~= "function" then return end
        counter = counter + 1

        local prefix = ""
        for _ = 1, 6 do
            local idx = math.random(1, #ALPHABET)
            prefix = prefix .. ALPHABET:sub(idx, idx)
        end

        local digits = ""
        for _ = 1, 4 do
            digits = digits .. string.char(math.random(48, 57))
        end

        local key = prefix .. "_" .. digits .. counter
        registry[key] = fn
        keys[#keys + 1] = key
    end

    pcall(function() register(loadstring) end)
    pcall(function() register(load) end)
    pcall(function()
        if syn and syn.loadstring then register(syn.loadstring) end
    end)

    local function pick(source)
        if #keys == 0 then error("exec pool empty") end
        local fn = registry[keys[math.random(1, #keys)]]
        if type(fn) ~= "function" then error("exec fn invalid") end
        return fn(source)
    end

    -- The original wraps `pick` in 4 identity closures; no behavioural effect.
    return pick
end)()


----------------------------------------------------------------------
-- Pool of HTTP request functions (request / http_request / syn.request /
-- http.request), also picked at random.
----------------------------------------------------------------------
local requestPool = (function()
    local registry = {}
    local keys     = {}
    local counter  = 0

    local function register(fn)
        if type(fn) ~= "function" then return end
        counter = counter + 1

        local key = ""
        for _ = 1, 12 do
            key = key .. string.char(math.random(65, 90))
        end
        key = key .. "_" .. tostring(counter)

        registry[key] = fn
        keys[#keys + 1] = key
    end

    pcall(function() register(request) end)
    pcall(function() if syn and syn.request then register(syn.request) end end)
    pcall(function() if http and http.request then register(http.request) end end)
    pcall(function() register(http_request) end)

    return {
        get = function()
            if #keys == 0 then return nil end
            return registry[keys[math.random(1, #keys)]]
        end,
        size = #keys,
    }
end)()

-- Send an HTTP request through a random request function.
-- Accepts a string (-> GET) or a request table.
local function httpRequest(req)
    if type(req) == "string" then
        req = { Url = req, Method = "GET" }
    end

    local fn = requestPool.get()
    if not fn then
        return nil, "no req fn"
    end

    local ok, response = pcall(fn, req)
    if not ok then
        return nil, tostring(response)
    end
    return response
end


----------------------------------------------------------------------
-- Environment sanity check (anti-tamper).
-- Returns true, or false + reason.
----------------------------------------------------------------------
local function checkEnvironment()
    if type(loadstring) ~= "function" then
        return false, "loadstring missing"
    end

    -- loadstring must be a native (C) function, not a Lua hook
    local ok, info = pcall(debug.getinfo, loadstring, "S")
    if ok and info and info.what ~= "C" then
        return false, "loadstring hooked"
    end

    local fn = loadstring("return 9999")
    if type(fn) ~= "function" then
        return false, "loadstring test failed"
    end
    if fn() ~= 9999 then
        return false, "loadstring wrong value"
    end

    if requestPool.size < 1 then
        return false, "no request fn"
    end

    return true
end

local envOk, envReason = checkEnvironment()
if not envOk then
    warn("[MAWW] env: " .. tostring(envReason))
    return
end


----------------------------------------------------------------------
-- Client identity sent to the server
----------------------------------------------------------------------
local placeId = tostring(game.PlaceId)

local username = "Unknown"
pcall(function() username = Players.LocalPlayer.Name end)

local hwid = "Unknown"
pcall(function()
    hwid = game:GetService("RbxAnalyticsService"):GetClientId()
end)

if type(hwid) ~= "string" or #hwid < 8 then
    warn("[MAWW] HWID tidak terbaca")   -- "HWID unreadable"
    return
end


----------------------------------------------------------------------
-- Ban detection.
-- If a server response contains "Reason :" or "LocalPlayer:Kick" the body
-- is treated as a kick/ban script: it is compiled AND EXECUTED
-- (pcall(fn)), then the caller aborts with "BANNED".
----------------------------------------------------------------------
local function isBanResponse(body)
    if type(body) ~= "string" then return false end

    if body:find("Reason :", 1, true) or body:find("LocalPlayer:Kick", 1, true) then
        local fn = compile(body)
        if fn then pcall(fn) end
        return true
    end
    return false
end


----------------------------------------------------------------------
-- Base64 decode (standard alphabet).
-- Uses crypt.base64decode if the executor has it, otherwise a manual
-- implementation (the original does it through a "0"/"1" bit string).
----------------------------------------------------------------------
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function base64Decode(input)
    if crypt and crypt.base64decode then
        local ok, result = pcall(crypt.base64decode, input)
        if ok and result then return result end
    end

    -- strip every character that is not part of the alphabet or '='
    input = input:gsub("[^" .. B64 .. "=]", "")

    -- every char -> 6 bits ('=' -> nothing)
    local bits = input:gsub(".", function(ch)
        if ch == "=" then return "" end
        local value = B64:find(ch, 1, true) - 1
        local out = ""
        for p = 6, 1, -1 do
            if (value % 2 ^ p) - (value % 2 ^ (p - 1)) > 0 then
                out = out .. "1"
            else
                out = out .. "0"
            end
        end
        return out
    end)

    -- 8 bits -> 1 byte
    local bytes = {}
    for i = 1, #bits - 7, 8 do
        local byte = 0
        for j = 0, 7 do
            if bits:sub(i + j, i + j) == "1" then
                byte = byte + 2 ^ (7 - j)
            end
        end
        bytes[#bytes + 1] = string.char(byte)
    end
    return table.concat(bytes)
end


----------------------------------------------------------------------
-- Key derivation: seed string -> 32-byte key table.
-- key[i] = (sum of bytes at positions i, i+32, i+64... + count*7) % 256
----------------------------------------------------------------------
local function deriveKey(seed)
    local seedBytes = {}
    for i = 1, #seed do
        seedBytes[i] = string.byte(seed, i)
    end

    local key = {}
    for i = 1, 32 do
        local sum, count = 0, 0
        for pos = i, #seedBytes, 32 do
            sum = (sum + seedBytes[pos]) % 256
            count = count + 1
        end
        key[i] = (sum + count * 7) % 256
    end
    return key
end


----------------------------------------------------------------------
-- Repeating-key XOR over a string
----------------------------------------------------------------------
local function xorDecrypt(data, key)
    local out = {}
    for i = 1, #data do
        local byte    = string.byte(data, i)
        local keyByte = key[((i - 1) % #key) + 1]

        local x
        if bit32 and bit32.bxor then
            x = bit32.bxor(byte, keyByte)
        else
            -- manual XOR fallback
            local a, b, result, place = byte, keyByte, 0, 1
            for _ = 1, 8 do
                if (a % 2) ~= (b % 2) then result = result + place end
                a, b, place = math.floor(a / 2), math.floor(b / 2), place * 2
            end
            x = result
        end
        out[i] = string.char(x)
    end
    return table.concat(out)
end


----------------------------------------------------------------------
-- Step 1 + 2: authenticate, then request the encrypted payload.
-- Returns { payload = <table with total/chunks>, token = <string> }
-- or nil + error message.
----------------------------------------------------------------------
local function fetchPayload()
    local headers = {
        ["Content-Type"] = "application/json",
        ["X-Maww-Tag"]   = TAG_VALUE,
        ["User-Agent"]   = "Roblox/WinInet",
    }

    -- /auth
    local authResp, authErr = httpRequest({
        Url     = AUTH_URL,
        Method  = "POST",
        Headers = headers,
        Body    = HttpService:JSONEncode({
            place_id = placeId,
            username = username,
            hwid     = hwid,
            ts       = tostring(os.time()),
        }),
    })
    if not authResp then
        return nil, "auth: " .. tostring(authErr)
    end
    if authResp.StatusCode ~= 200 then
        return nil, "auth status " .. tostring(authResp.StatusCode)
    end
    if isBanResponse(authResp.Body) then
        return nil, "BANNED"
    end

    local authData
    local decodedOk = pcall(function()
        authData = HttpService:JSONDecode(authResp.Body)
    end)
    if not decodedOk or not authData or not authData.token then
        return nil, "auth invalid"
    end

    task.wait(0.3)

    -- /load (needs the token + challenge from /auth)
    local loadResp, loadErr = httpRequest({
        Url     = LOAD_URL,
        Method  = "POST",
        Headers = headers,
        Body    = HttpService:JSONEncode({
            token    = authData.token,
            challenge = authData.challenge,
            hwid     = hwid,
            place_id = placeId,
            ts       = tostring(os.time()),
        }),
    })
    if not loadResp then
        return nil, "load: " .. tostring(loadErr)
    end
    if loadResp.StatusCode ~= 200 then
        return nil, "load status " .. tostring(loadResp.StatusCode)
    end
    if isBanResponse(loadResp.Body) then
        return nil, "BANNED"
    end

    local payload
    local parsedOk = pcall(function()
        payload = HttpService:JSONDecode(loadResp.Body)
    end)
    if not parsedOk or not payload or not payload.chunks then
        return nil, "payload invalid"
    end

    return { payload = payload, token = authData.token }
end


----------------------------------------------------------------------
-- Step 3: rebuild the script from the chunk list.
-- Each chunk: base64 -> XOR with key derived from "<token>|<index>|<placeId>".
-- Decrypted chunks are joined with "\n".
----------------------------------------------------------------------
local function rebuildSource(payload, token)
    local total, chunks = payload.total, payload.chunks

    if type(total) ~= "number" or total < 1 then
        return nil, "invalid total"
    end
    if type(chunks) ~= "table" or #chunks ~= total then
        return nil, "invalid chunks"
    end

    local byIndex = {}
    for _, chunk in ipairs(chunks) do
        if type(chunk.idx) ~= "number" or type(chunk.data) ~= "string" then
            return nil, "chunk malformed"
        end
        if chunk.idx < 0 or chunk.idx >= total then
            return nil, "idx out of range"
        end
        byIndex[chunk.idx] = chunk.data
    end

    for i = 0, total - 1 do
        if not byIndex[i] then
            return nil, "missing chunk " .. i
        end
    end

    local parts = {}
    for i = 0, total - 1 do
        local raw = base64Decode(byIndex[i])
        local key = deriveKey(token .. "|" .. i .. "|" .. placeId)
        parts[#parts + 1] = xorDecrypt(raw, key)
    end
    return table.concat(parts, "\n")
end


----------------------------------------------------------------------
-- Main flow
----------------------------------------------------------------------
local result, lastError
for attempt = 1, MAX_RETRIES do
    if attempt > 1 then
        warn("[MAWW] retry " .. attempt .. "/" .. MAX_RETRIES)
        task.wait(RETRY_DELAY)
    end

    local data, err = fetchPayload()
    if data then
        result = data
        break
    end

    lastError = err
    if err == "BANNED" then
        warn("[MAWW] Akun kena blacklist.")   -- "Account is blacklisted."
        return
    end
    warn("[MAWW] attempt " .. attempt .. ": " .. tostring(err))
end

if not result then
    warn("[MAWW] gagal semua: " .. tostring(lastError))   -- "all failed"
    return
end

local source, rebuildErr
local rebuildOk, rebuildCrash = pcall(function()
    source, rebuildErr = rebuildSource(result.payload, result.token)
end)
if not rebuildOk then
    warn("[MAWW] rebuild crashed: " .. tostring(rebuildCrash))
    return
end
if not source then
    warn("[MAWW] rebuild failed: " .. tostring(rebuildErr or "unknown"))
    return
end

if type(source) ~= "string" or #source < 50 then
    warn("[MAWW] src invalid: " .. tostring(#source))
    return
end

local fn, compileErr = compile(source)
if not fn then
    warn("[MAWW] compile: " .. tostring(compileErr))
    warn("[MAWW] preview: " .. tostring(source:sub(1, 200)))
    return
end

local ran, runtimeErr = pcall(fn)
if not ran then
    warn("[MAWW] runtime: " .. tostring(runtimeErr))
end
