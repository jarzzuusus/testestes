--[[
    MAWW loader - minimal version.
    Removed: loadstring hook / anti-tamper checks (native-function check, "return 9999"
    test), ban-script detection, HWID length check, random function pools, retries.
    Kept: the loader itself (auth -> load -> rebuild -> loadstring -> run).
]]

local AUTH_URL = "https://free-mawwhub.vercel.app/api/auth"
local LOAD_URL = "https://free-mawwhub.vercel.app/api/load"
local TAG      = "maww-v1"   -- header X-Maww-Tag

local HttpService = game:GetService("HttpService")
local Players     = game:GetService("Players")

local load_fn = loadstring or load
local http    = request or http_request or (syn and syn.request) or (http and http.request)

local placeId  = tostring(game.PlaceId)
local username = "Unknown"
pcall(function() username = Players.LocalPlayer.Name end)
local hwid = "Unknown"
pcall(function() hwid = game:GetService("RbxAnalyticsService"):GetClientId() end)

local headers = {
    ["Content-Type"] = "application/json",
    ["X-Maww-Tag"]   = TAG,
    ["User-Agent"]   = "Roblox/WinInet",
}

local function post(url, body)
    local res = http({
        Url = url, Method = "POST", Headers = headers,
        Body = HttpService:JSONEncode(body),
    })
    assert(res and res.StatusCode == 200, "HTTP " .. tostring(res and res.StatusCode))
    return HttpService:JSONDecode(res.Body)
end


-- base64 decode (standard alphabet)
local B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

local function base64Decode(input)
    if crypt and crypt.base64decode then
        local ok, result = pcall(crypt.base64decode, input)
        if ok and result then return result end
    end
    input = input:gsub("[^" .. B64 .. "=]", "")
    local bits = input:gsub(".", function(ch)
        if ch == "=" then return "" end
        local value = B64:find(ch, 1, true) - 1
        local out = ""
        for p = 6, 1, -1 do
            out = out .. (((value % 2 ^ p) - (value % 2 ^ (p - 1)) > 0) and "1" or "0")
        end
        return out
    end)
    local bytes = {}
    for i = 1, #bits - 7, 8 do
        local byte = 0
        for j = 0, 7 do
            if bits:sub(i + j, i + j) == "1" then byte = byte + 2 ^ (7 - j) end
        end
        bytes[#bytes + 1] = string.char(byte)
    end
    return table.concat(bytes)
end

-- seed string -> 32-byte key
local function deriveKey(seed)
    local key = {}
    for i = 1, 32 do
        local sum, count = 0, 0
        for pos = i, #seed, 32 do
            sum = (sum + seed:byte(pos)) % 256
            count = count + 1
        end
        key[i] = (sum + count * 7) % 256
    end
    return key
end

local function xorDecrypt(data, key)
    local out = {}
    for i = 1, #data do
        out[i] = string.char(bit32.bxor(data:byte(i), key[((i - 1) % #key) + 1]))
    end
    return table.concat(out)
end


-- 1) auth  2) load  3) rebuild  4) run
local auth = post(AUTH_URL, {
    place_id = placeId, username = username, hwid = hwid, ts = tostring(os.time()),
})
task.wait(0.3)

local payload = post(LOAD_URL, {
    token = auth.token, challenge = auth.challenge,
    hwid = hwid, place_id = placeId, ts = tostring(os.time()),
})

local byIndex = {}
for _, chunk in ipairs(payload.chunks) do byIndex[chunk.idx] = chunk.data end

local parts = {}
for i = 0, payload.total - 1 do
    parts[#parts + 1] = xorDecrypt(
        base64Decode(byIndex[i]),
        deriveKey(auth.token .. "|" .. i .. "|" .. placeId))
end
local source = table.concat(parts, "\n")

-- optional: print(source) here to inspect the final script instead of running it
load_fn(source)()
