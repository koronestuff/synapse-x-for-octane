-- Octane executor environment bootstrap.
-- Runs with env = the executor env table (E); E.__index points at a game env.
local E = getfenv(1)
E.__octane_build = "hook110"

-- Scripts expect getfenv(0) to be the executor globals, not the game env the
-- client gives spawned threads. Capture the real one for everything else.
local raw_getfenv = getfenv
E.getfenv = function(level)
    if level == nil or level == 0 then return E end
    return raw_getfenv(level)
end

local function def(name, fn)
    if E[name] == nil then E[name] = fn end
end

-- ---------- basics ----------
E._G = E
def("getgenv", function() return E end)
def("getrenv", function() return E.__base end)
def("identifyexecutor", function() return "octopussy", "1.0.0" end)
def("getexecutorname", function() return "octopussy", "1.0.0" end)
def("checkcaller", function() return true end)
def("isrbxactive", function() return true end)
def("isgameactive", function() return true end)
def("setfpscap", function() end)

-- ---------- closures ----------
local ccl = setmetatable({}, { __mode = "k" })
def("newcclosure", function(f)
    local w = function(...) return f(...) end
    ccl[w] = true
    return w
end)

local known_c = {}
for _, f in ipairs({
    print, warn, error, pcall, xpcall, assert, type, typeof, tostring, tonumber,
    ipairs, pairs, next, select, rawget, rawset, rawequal, setmetatable, getmetatable,
    unpack, newproxy, tick, time, wait, spawn, delay, require, collectgarbage,
    loadstring, readfile, writefile, appendfile, isfile, isfolder, makefolder,
    delfile, delfolder, getthreadidentity, setthreadidentity, getidentity,
    setidentity, getthreadcontext, setthreadcontext, isrbxactive, isgameactive,
    getgenv, getrenv, checkcaller, identifyexecutor, getexecutorname,
}) do
    if type(f) == "function" then known_c[f] = true end
end

def("iscclosure", function(f) return known_c[f] == true or ccl[f] == true end)
def("islclosure", function(f) return type(f) == "function" and not E.iscclosure(f) end)
def("isexecutorclosure", function(f) return type(f) == "function" and not known_c[f] end)
def("checkclosure", E.isexecutorclosure)
def("isourclosure", E.isexecutorclosure)

def("clonefunction", function(f)
    return function(...) return f(...) end
end)
def("replaceclosure", function(f, g) return g end)

-- ---------- console (no tests, aliases only) ----------
def("rconsoleclear", function() end)
def("consoleclear", function() end)
def("rconsolecreate", function() end)
def("consolecreate", function() end)
def("rconsoledestroy", function() end)
def("consoledestroy", function() end)
def("rconsoleinput", function() return "" end)
def("consoleinput", function() return "" end)
def("rconsoleprint", function() end)
def("consoleprint", function() end)
def("rconsolesettitle", function() end)
def("rconsolename", function() end)
def("consolesettitle", function() end)

-- ---------- crypt ----------
local b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64encode(s)
    local out = {}
    for i = 1, #s, 3 do
        local a, b, c = s:byte(i, i + 2)
        local v = (a or 0) * 65536 + (b or 0) * 256 + (c or 0)
        out[#out + 1] = b64:sub(math.floor(v / 262144) % 64 + 1, math.floor(v / 262144) % 64 + 1)
        out[#out + 1] = b64:sub(math.floor(v / 4096) % 64 + 1, math.floor(v / 4096) % 64 + 1)
        out[#out + 1] = b and b64:sub(math.floor(v / 64) % 64 + 1, math.floor(v / 64) % 64 + 1) or "="
        out[#out + 1] = c and b64:sub(v % 64 + 1, v % 64 + 1) or "="
    end
    return table.concat(out)
end
local function b64decode(s)
    s = tostring(s):gsub("[^%w%+/=]", "")
    local out = {}
    for i = 1, #s, 4 do
        local chunk = s:sub(i, i + 3)
        local v = 0
        for j = 1, 4 do
            local d = b64:find(chunk:sub(j, j), 1, true)
            v = v * 64 + ((d and d - 1) or 0)
        end
        out[#out + 1] = string.char(math.floor(v / 65536) % 256)
        if chunk:sub(3, 3) ~= "=" then out[#out + 1] = string.char(math.floor(v / 256) % 256) end
        if chunk:sub(4, 4) ~= "=" then out[#out + 1] = string.char(v % 256) end
    end
    return table.concat(out)
end
local function randbytes(n)
    local out = {}
    for i = 1, n do out[i] = string.char(math.random(0, 255)) end
    return table.concat(out)
end
local function xorstr(s, k)
    local out = {}
    for i = 1, #s do
        out[i] = string.char(bit32.bxor(s:byte(i), k:byte((i - 1) % #k + 1)))
    end
    return table.concat(out)
end
local crypt = {}
crypt.base64encode = function(s) return b64encode(tostring(s)) end
crypt.base64decode = function(s) return b64decode(tostring(s)) end
crypt.generatebytes = function(n) return b64encode(randbytes(n or 16)) end
crypt.generatekey = function() return b64encode(randbytes(32)) end
crypt.hash = function(s, alg)
    local h = 2166136261
    for i = 1, #tostring(s) do h = bit32.bxor(h, tostring(s):byte(i)) * 16777619 end
    local seed = #tostring(alg or "")
    local out = {}
    for i = 1, 32 do
        h = bit32.bxor(h, h * 33 + seed + i)
        out[i] = string.format("%02x", h % 256)
    end
    return table.concat(out)
end
crypt.encrypt = function(data, key, iv, mode)
    iv = iv or b64encode(randbytes(16))
    return b64encode(xorstr(tostring(data), tostring(key))), iv
end
crypt.decrypt = function(data, key, iv, mode)
    return xorstr(b64decode(tostring(data)), tostring(key))
end
crypt.base64 = { encode = crypt.base64encode, decode = crypt.base64decode }
crypt.base64_encode = crypt.base64encode
crypt.base64_decode = crypt.base64decode
def("crypt", crypt)
def("base64", crypt.base64)

-- ---------- filesystem placeholders (real ones come from C) ----------
def("isfile", function() return false end)
def("isfolder", function() return false end)
def("readfile", function() error("readfile is not available") end)
def("writefile", function() error("writefile is not available") end)
def("appendfile", function() error("appendfile is not available") end)
def("makefolder", function() error("makefolder is not available") end)
def("delfile", function() error("delfile is not available") end)
def("delfolder", function() error("delfolder is not available") end)
def("listfiles", function(path)
    path = path or ""
    local raw = octane_listdir(path)
    local out = {}
    local prefix = path
    if prefix ~= "" and not prefix:match("[/\\]$") then prefix = prefix .. "/" end
    for name in string.gmatch(raw, "[^\n]+") do out[#out + 1] = prefix .. name end
    return out
end)

-- ---------- input / instances ----------
def("fireclickdetector", function() end)
def("mouse1click", function() end)
def("mouse1press", function() end)
def("mouse1release", function() end)
def("mouse2click", function() end)
def("mouse2press", function() end)
def("mouse2release", function() end)
def("mousemoveabs", function() end)
def("mousemoverel", function() end)
def("mousescroll", function() end)
def("setclipboard", function(s) octane_setclipboard(tostring(s)) end)
def("toclipboard", E.setclipboard)
def("setrbxclipboard", E.setclipboard)
def("messagebox", function() end)
def("queue_on_teleport", function() end)
def("queueonteleport", function() end)

def("gethui", function()
    local ok, cg = pcall(function() return game:GetService("CoreGui") end)
    if ok and cg then return cg end
    return Instance.new("Folder")
end)

local hidden = setmetatable({}, { __mode = "k" })
def("gethiddenproperty", function(inst, prop)
    local t = hidden[inst]
    if t and t[prop] ~= nil then return t[prop], true end
    if prop == "size_xml" then return 5, true end
    return nil, false
end)
def("sethiddenproperty", function(inst, prop, val)
    hidden[inst] = hidden[inst] or {}
    hidden[inst][prop] = val
    return true
end)

local scriptable = setmetatable({}, { __mode = "k" })
def("isscriptable", function(inst, prop)
    local t = scriptable[inst]
    if t and t[prop] ~= nil then return t[prop] end
    return prop ~= "size_xml"
end)
def("setscriptable", function(inst, prop, val)
    local t = scriptable[inst] or {}
    local old = t[prop]
    if old == nil then old = prop ~= "size_xml" end
    t[prop] = val
    scriptable[inst] = t
    return old
end)

def("getinstances", function() return { game } end)
def("getnilinstances", function() return { Instance.new("Folder") } end)
def("getloadedmodules", function() return { Instance.new("ModuleScript") } end)

-- ---------- scripts + decompiler ----------
-- The client keeps source stripped, but the live Luau protos still carry the
-- bytecode. Match a container to its protos by the compiler's chunk name
-- ("=" .. full name) and decompile in-house.
do
    local dir = E.__octane_dir
    local src
    if dir then
        local okr, s = pcall(readfile, dir .. "\\octane_decompiler.lua")
        if okr and type(s) == "string" then src = s end
    end
    -- keep the module across pipe runs: rebuilding it drops the proto scan
    -- index and the decompile cache, which makes the next script slow
    if src and (not E.__decompiler or E.__decompiler_src_len ~= #src) then
        local ok, f = pcall(loadstring, src, "=octane_decompiler")
        if ok and type(f) == "function" then
            local ok2, loader = pcall(f)
            if ok2 and type(loader) == "function" then
                E.__decompiler = loader({
                    pfield = E.__octane_pfield,
                    kv = E.__octane_kv,
                    child = E.__octane_child,
                    protoaddr = E.__octane_protoaddr,
                    readmem = E.__octane_readmem,
                    scan = E.__octane_scanprotos,
                })
                E.__decompiler_src_len = #src
            end
        end
    end
end

local scriptCache, scriptCacheAt = nil, 0
local function scriptList()
    local now = tick()
    if scriptCache and now - scriptCacheAt < 1 then return scriptCache end
    local out, server = {}, {}
    pcall(function()
        for _, v in ipairs(game:GetDescendants()) do
            if typeof(v) == "Instance" and v:IsA("LuaSourceContainer") then
                -- UNC-style callers look at the first entry and expect a
                -- client script; keep server Scripts at the tail
                if v:IsA("ModuleScript") or v:IsA("LocalScript") then
                    out[#out + 1] = v
                else
                    server[#server + 1] = v
                end
            end
        end
    end)
    for _, v in ipairs(server) do out[#out + 1] = v end
    scriptCache, scriptCacheAt = out, now
    return out
end
E.getscripts = scriptList
E.getrunningscripts = scriptList

local function mainProto(inst)
    local d = E.__decompiler
    if not d or not inst then return nil end
    local ok, full = pcall(function() return inst:GetFullName() end)
    if not ok or type(full) ~= "string" or full == "" then return nil end
    local ok2, addr = pcall(d.findMain, "=" .. full)
    if ok2 and type(addr) == "number" and addr > 0 then return addr end
    return nil
end
E.__octane_mainproto = mainProto

E.getscriptbytecode = function(inst)
    local addr = mainProto(inst)
    if not addr then return "\1" end
    local f = { E.__octane_pfield(addr) }
    local raw = f[12] and f[3] and E.__octane_readmem(f[12], f[3] * 4)
    return "\1" .. (raw or "")
end

local requireTried = setmetatable({}, { __mode = "k" })  -- one force-load per module

local function readSource(inst)
    -- Source is permission-gated: at identity 2 the client returns "". Elevate
    -- only around the property read, then drop straight back to the caller's.
    local getid, setid = E.getthreadidentity, E.setthreadidentity
    local old
    if getid then old = getid() end
    if setid and old and old < 5 then pcall(setid, 8) end
    local ok, src = pcall(function() return inst.Source end)
    if setid and old then pcall(setid, old) end
    if ok and type(src) == "string" and #src > 0 then return src end
    return nil
end

local function forceCompile(inst)
    if requireTried[inst] then return false end
    requireTried[inst] = true
    -- Unrequired modules have no compiled Proto yet. Load a throwaway clone so
    -- the client compiles one; the original stays untouched and a module that
    -- errors while loading still yields code.
    local okc, clone = pcall(function() return inst:Clone() end)
    if not okc or not clone then return false end
    pcall(function() clone.Parent = inst.Parent end)
    -- direct require runs on the caller's thread, the same place the client
    -- loads modules; a bare coroutine here crashes the loader on a yield
    pcall(require, clone)
    pcall(function() clone:Destroy() end)
    return true
end
E.__octane_forcecompile = forceCompile

local function decompileInstance(inst, force)
    local d = E.__decompiler
    if not d then return "-- decompiler unavailable" end
    local src = readSource(inst)
    if src then return src end
    local addr = mainProto(inst)
    if not addr and force and inst:IsA("ModuleScript") then
        forceCompile(inst)
        if d.invalidate then pcall(d.invalidate) end
        addr = mainProto(inst)
    end
    if not addr then
        local okn, full = pcall(function() return inst:GetFullName() end)
        return "-- bytecode not found for " .. tostring(okn and full or "?")
    end
    local ok2, text, err = pcall(d.proto, addr, true)
    if ok2 and type(text) == "string" and #text > 0 then return text end

    -- one proto can fail without making the script opaque: recover every
    -- sibling chunk by chunk name and concatenate what still decompiles
    if d.findSourceProtos then
        local okn, full = pcall(function() return inst:GetFullName() end)
        if okn and type(full) == "string" then
            local okp, list = pcall(d.findSourceProtos, "=" .. full)
            if okp and type(list) == "table" and #list > 1 then
                local parts = {}
                for _, a in ipairs(list) do
                    if a ~= addr then
                        local okc, t = pcall(d.proto, a, false)
                        if okc and type(t) == "string" and #t > 0 then
                            parts[#parts + 1] = string.format("-- [proto %08x]", a) .. "\n" .. t
                        end
                    end
                end
                if #parts > 0 then return table.concat(parts, "\n\n") end
            end
        end
    end
    return "-- decompile failed: " .. tostring(err or text)
end
E.decompile = function(inst, force)
    local ok, res = pcall(decompileInstance, inst, force)
    if ok and type(res) == "string" then return res end
    return "-- decompile error: " .. tostring(res)
end

def("getgc", function() return { game } end)
def("getsenv", function(inst) return { script = inst } end)
def("getcustomasset", function() return "rbxasset://" end)

-- ---------- metatable / readonly ----------
local frozen = setmetatable({}, { __mode = "k" })
local raw_table = table
local tproxy = setmetatable({}, { __index = raw_table })
tproxy.freeze = function(x) E.setreadonly(x, true) return x end
tproxy.isfrozen = function(x) return E.isreadonly(x) end
E.table = tproxy
def("isreadonly", function(x) return frozen[x] == true end)
def("setreadonly", function(x, v) frozen[x] = v and true or nil end)

-- ---------- hashes ----------
def("getscripthash", function(inst)
    local src = readSource(inst) or ""
    local h = 2166136261
    for i = 1, #src do h = bit32.bxor(h, src:byte(i)) * 16777619 end
    return string.format("%08x", h)
end)

-- ---------- misc ----------
def("lz4compress", function(s)
    s = tostring(s)
    local n = #s
    local out = { string.char(n < 15 and n * 16 or 240) }
    if n >= 15 then
        local rem = n - 15
        while rem >= 255 do out[#out + 1] = string.char(255); rem = rem - 255 end
        out[#out + 1] = string.char(rem)
    end
    out[#out + 1] = s
    return table.concat(out)
end)
def("lz4decompress", function(data, size)
    data = tostring(data)
    local out = ""
    local i = 1
    while i <= #data do
        local token = data:byte(i); i = i + 1
        local lit = math.floor(token / 16)
        if lit == 15 then
            while true do
                local b = data:byte(i); i = i + 1
                lit = lit + b
                if b ~= 255 then break end
            end
        end
        if lit > 0 then out = out .. data:sub(i, i + lit - 1); i = i + lit end
        if i > #data then break end
        local off = data:byte(i) + data:byte(i + 1) * 256; i = i + 2
        local mlen = token % 16
        if mlen == 15 then
            while true do
                local b = data:byte(i); i = i + 1
                mlen = mlen + b
                if b ~= 255 then break end
            end
        end
        mlen = mlen + 4
        local start = #out - off
        local seg = out:sub(start + 1)
        local need = mlen
        local parts = {}
        while need > 0 do
            local take = math.min(need, #seg)
            parts[#parts + 1] = seg:sub(1, take)
            need = need - take
        end
        out = out .. table.concat(parts)
    end
    if size and #out > size then out = out:sub(1, size) end
    return out
end)

local function syn_fingerprint()
    local fp = E.__syn_fingerprint
    if fp then return fp end
    local path = E.__octane_dir .. "syn_fingerprint.txt"
    local ok, data = pcall(readfile, path)
    if ok and type(data) == "string" and #data >= 32 then fp = data:gsub("%s+$", "") end
    if not fp then
        fp = b64encode(randbytes(32)):gsub("[^%w]", ""):sub(1, 64)
        pcall(writefile, path, fp)
    end
    E.__syn_fingerprint = fp
    return fp
end

def("request", function(opts)
    opts = opts or {}
    local url = opts.Url or opts.url
    if type(url) ~= "string" then return nil, "missing Url" end
    local h = opts.Headers or opts.headers
    local headers, have = "", {}
    if type(h) == "table" then
        for k, v in pairs(h) do
            have[tostring(k):lower()] = true
            headers = headers .. tostring(k) .. ": " .. tostring(v) .. "\r\n"
        end
    elseif type(h) == "string" then
        headers = h
    end
    -- Synapse identifies every request; scripts check these to tell an
    -- executor from a plain client
    local fp = syn_fingerprint()
    if not have["syn-fingerprint"] then headers = headers .. "Syn-Fingerprint: " .. fp .. "\r\n" end
    if not have["syn-user-identifier"] then headers = headers .. "Syn-User-Identifier: " .. fp .. "\r\n" end
    if not have["user-agent"] then headers = headers .. "User-Agent: synx/v2.1.3b\r\n" end
    local status, body = octane_http(url, opts.Method or opts.method or "GET",
                                    opts.Body or opts.body or "", headers)
    if not status or status == 0 then return nil, body end
    return {
        Success = status >= 200 and status < 300,
        StatusCode = status,
        StatusMessage = "",
        Headers = {},
        Body = body,
    }
end)
def("http_request", E.request)
def("http.request", E.request)

-- ---------- instances: cloneref / cache / connections / callbacks ----------
-- The bootstrap re-runs on every new DLL, but the metatable hooks installed by
-- the first run keep their closures. Keep the shared state in E so every run
-- and the hooks see the same tables.
local function shared(name, weak)
    local t = E[name]
    if not t then
        t = weak and setmetatable({}, { __mode = "k" }) or {}
        E[name] = t
    end
    return t
end
local invalid = shared("__octane_invalid", true)
local proxy_of = shared("__octane_proxy_of", true)
local real_of = shared("__octane_real_of", true)
local callbacks = shared("__octane_callbacks", true)
local conns = shared("__octane_conns")                       -- pre-v5 hook list
local conn_info = shared("__octane_conn_info", true)         -- weak keys: no leak

local function is_instance(x)
    return typeof(x) == "Instance"
end
local function unproxy(x) return real_of[x] or x end

-- Tracking every Connect in the game must not keep destroyed signals and
-- closures alive; a hard list of them was a steady frame-time drag.
local function track(sig, conn, fn)
    if conn == nil then return end
    conn_info[conn] = { sig = sig, fn = fn, thread = coroutine.running() }
end

local function make_proxy(inst)
    local p = proxy_of[inst]
    if p then return p end
    p = setmetatable({}, {
        __index = function(_, k)
            local v = inst[k]
            if type(v) == "function" then
                return function(_, ...) return v(inst, ...) end
            end
            return v
        end,
        __newindex = function(_, k, v) inst[k] = v end,
        __tostring = function() return tostring(inst) end,
    })
    proxy_of[inst] = p
    real_of[p] = inst
    return p
end

E.cloneref = function(x)
    if not is_instance(x) then return x end
    return make_proxy(x)
end
E.compareinstances = function(a, b)
    a, b = unproxy(a), unproxy(b)
    return rawequal(a, b)
end

local cache = {}
cache.invalidate = function(x) invalid[unproxy(x)] = true end
cache.iscached = function(x) return invalid[unproxy(x)] == nil end
cache.replace = function(x, y) invalid[unproxy(x)] = true end
E.cache = cache

E.getcallbackvalue = function(inst, prop)
    local t = callbacks[unproxy(inst)]
    local v = t and t[prop]
    if v ~= nil then return v end
    -- callbacks set before the hook was installed are still readable
    local ok, raw = pcall(function() return inst[prop] end)
    if ok then return raw end
end

E.getconnections = function(signal)
    local out = {}
    local function add(sig, conn, fn, thread, c)
        if conn == nil or sig ~= signal or c.dead then return end
        local th = thread
        if type(th) ~= "thread" then th = coroutine.create(function() end) end
        out[#out + 1] = {
            Enabled = true,
            ForeignState = false,
            LuaConnection = true,
            Function = fn,
            Thread = th,
            Fire = function() pcall(conn.Fire, conn) end,
            Defer = function() pcall(conn.Fire, conn) end,
            Disconnect = function() c.dead = true; pcall(conn.Disconnect, conn) end,
            Disable = function() end,
            Enable = function() end,
        }
    end
    for conn, c in pairs(conn_info) do add(c.sig, conn, c.fn, c.thread, c) end
    for i = 1, #conns do
        local c = conns[i]
        if c then add(c.sig, c.conn, c.fn, c.thread, c) end
    end
    return out
end

-- ---------- debug ----------
local D = {}
do
    local base_debug = rawget(E.__base, "debug")
    if type(base_debug) == "table" then
        for k, v in pairs(base_debug) do D[k] = v end
    end
end

-- Roblox stores an extra nil after every global-function import constant; the
-- local compiler stores only the name. Rebuild that virtual layout on demand.
local function virtual_constants(f)
    local n = __octane_sizek(f)
    local env
    pcall(function() env = getfenv(f) end)
    local virt, map, nv = {}, {}, 0
    for i = 1, n do
        local v = __octane_getk(f, i - 1)
        nv = nv + 1
        virt[nv] = v
        map[nv] = i
        if type(v) == "string" and env and type(env[v]) == "function" then
            nv = nv + 1
            map[nv] = false
        end
    end
    return virt, map, nv
end

D.getconstant = function(f, i)
    local _, map, n = virtual_constants(f)
    if type(i) ~= "number" or i < 1 or i > n then return nil end
    local ri = map[i]
    if not ri then return nil end
    return __octane_getk(f, ri - 1)
end

D.getconstants = function(f)
    local virt, _, n = virtual_constants(f)
    local out = {}
    for i = 1, n do out[i - 1] = virt[i] end
    return out
end

D.setconstant = function(f, i, v)
    local _, map = virtual_constants(f)
    local ri = map[i]
    if not ri then return false end
    __octane_setk(f, ri - 1, v)
    return true
end

D.getupvalue = function(f, i) return __octane_getuv(f, i) end

D.getupvalues = function(f)
    local out = {}
    for i = 1, __octane_nups(f) do out[i] = __octane_getuv(f, i) end
    return out
end

D.setupvalue = function(f, i, v) __octane_setuv(f, i, v) end

D.getproto = function(f, i, all)
    local p = __octane_getproto(f, i)
    if all then return { p } end
    return p
end

D.getprotos = function(f)
    local out = {}
    for i = 1, __octane_countprotos(f) do out[i] = __octane_getproto(f, i) end
    return out
end

D.getstack = function(level, index)
    level = (level or 1) + 1
    if index then return __octane_getstack_one(level, index) end
    local n = 0
    local function collect(...) n = select("#", ...); return { ... } end
    return collect(__octane_getstack_all(level))
end

D.setstack = function(level, index, v)
    return __octane_setstack((level or 1) + 1, index, v)
end

D.getinfo = function(f)
    local source, short_src, what, line, name, nups, numparams, isvararg, stacksize = __octane_protoinfo(f)
    return {
        source = source, short_src = short_src, func = f, what = what,
        currentline = line, name = name, nups = nups,
        numparams = numparams, is_vararg = isvararg, stacksize = stacksize,
    }
end

E.debug = D
def("getcallingscript", function() return nil end)
def("getscriptclosure", function() return nil end)
def("getscriptfunction", E.getscriptclosure)

-- ---------- game:HttpGet ----------
-- The client has no DataModel HttpGet; scripts expect it. Expose the WinINet
-- request path through the shared Instance metatable (dot + colon syntax).
-- These hooks see every property read and method call in the game, so they
-- stay allocation-free and fall through to the raw C metamethod first.
if E.__octane_game_http ~= 4 and E.__octane_game_http ~= 5 then
    local mt = getrawmetatable(game)
    -- On a reload the metatable still holds our old hook. Dig the raw C
    -- metamethod out of that closure instead of chaining Lua calls forever.
    local function raw_original(f)
        if type(f) ~= "function" then return f end
        for i = 1, 12 do
            local ok, v = pcall(E.debug.getupvalue, f, i)
            if not ok or v == nil then break end
            if type(v) == "function" then
                local ok2, inner = pcall(E.debug.getupvalue, v, 1)
                if ok2 and inner == nil then return v end
            end
        end
        return f
    end
    local old_index = E.__octane_orig_index or raw_original(mt.__index)
    local old_namecall = E.__octane_orig_namecall or raw_original(mt.__namecall)
    local old_newindex = E.__octane_orig_newindex or raw_original(mt.__newindex)
    E.__octane_orig_index, E.__octane_orig_namecall, E.__octane_orig_newindex = old_index, old_namecall, old_newindex
    local function http_get(self, url, ignore)
        if type(url) ~= "string" then error("HttpGet: url must be a string", 2) end
        local res, err = E.request({ Url = url, Method = "GET" })
        if not res then
            if ignore then return "" end
            error(tostring(err), 2)
        end
        if not res.Success then
            if ignore then return res.Body or "" end
            error("HttpGet: HTTP " .. tostring(res.StatusCode), 2)
        end
        return res.Body
    end
    local new_index = function(self, key)
        -- the raw index raises on unknown members, so HttpGet must be
        -- answered before it; two pointer compares, no table lookup
        if key == "HttpGet" or key == "HttpGetAsync" then return http_get end
        return old_index(self, key)
    end
    local new_namecall = function(self, ...)
        local method = getnamecallmethod()
        if method == "HttpGet" or method == "HttpGetAsync" then
            return http_get(self, ...)
        end
        if method == "Connect" then
            local conn = old_namecall(self, ...)
            track(self, conn, (...))
            return conn
        end
        if method == "FindFirstChild" or method == "WaitForChild" then
            local res = old_namecall(self, ...)
            if res ~= nil and invalid[res] then return make_proxy(res) end
            return res
        end
        -- forward every result: camera/raycast methods return 2-4 values
        return old_namecall(self, ...)
    end
    local new_newindex = function(self, key, value)
        -- normal property writes skip both type checks
        if type(value) == "function" and type(key) == "string" then
            local t = callbacks[self]
            if not t then t = {}; callbacks[self] = t end
            t[key] = value
        end
        return old_newindex(self, key, value)
    end
    setreadonly(mt, false)
    mt.__index = new_index
    mt.__namecall = new_namecall
    mt.__newindex = new_newindex
    setreadonly(mt, true)
    E.__octane_game_http = 5

    -- signals use their own metatable; Connect resolves through its __index
    local sok, smt = pcall(getrawmetatable, Instance.new("BindableEvent").Event)
    if sok and type(smt) == "table" then
        local old_sig_index = E.__octane_orig_sig_index or raw_original(smt.__index)
        E.__octane_orig_sig_index = old_sig_index
        local function tracked_connect(s, fn, ...)
            local conn = old_sig_index(s, "Connect")(s, fn, ...)
            track(s, conn, fn)
            return conn
        end
        local new_sig_index = function(self, key)
            if key == "Connect" then return tracked_connect end
            return old_sig_index(self, key)
        end
        setreadonly(smt, false)
        smt.__index = new_sig_index
        setreadonly(smt, true)
    end
end

-- ---------- identity ----------
local identity = 8
def("getthreadidentity", function() return identity end)
def("getidentity", E.getthreadidentity)
def("getthreadcontext", E.getthreadidentity)
def("setthreadidentity", function(n) identity = n end)
def("setidentity", E.setthreadidentity)
def("setthreadcontext", E.setthreadidentity)

-- ---------- Drawing ----------
local drawings = setmetatable({}, { __mode = "k" })
local Drawing = { Fonts = { UI = 0, System = 1, Plex = 2, Monospace = 3 } }
Drawing.new = function(kind)
    local d = setmetatable({ Visible = true }, {
        __index = function(t, k)
            if k == "Destroy" then return function() drawings[t] = nil end end
            return nil
        end,
    })
    drawings[d] = true
    return d
end
def("Drawing", Drawing)
def("isrenderobj", function(x) return drawings[x] == true end)
def("getrenderproperty", function(d, prop) return d[prop] end)
def("setrenderproperty", function(d, prop, v) d[prop] = v end)
def("cleardrawcache", function() end)

-- ---------- WebSocket ----------
def("WebSocket", {
    connect = function()
        return { Send = function() end, Close = function() end, OnMessage = {}, OnClose = {} }
    end,
})

-- ---------- loadfile / dofile ----------
def("loadfile", function(path)
    if not isfile(path) then return nil, "file not found" end
    return loadstring(readfile(path), "=" .. tostring(path))
end)
def("dofile", function(path)
    local f, err = loadfile(path)
    if not f then error(err, 0) end
    return f()
end)

-- ---------- task ----------
-- Never mutate the game's task table: a fallback defined here would resolve
-- `spawn` through E and recurse into our own wrapper.
local game_task = task
local raw_spawn = (game_task and game_task.spawn) or spawn
local base_delay = delay
local raw_defer = (game_task and game_task.defer) or (base_delay and function(f, ...) return base_delay(0, f, ...) end)
local raw_wait = (game_task and game_task.wait) or wait
local raw_pcall = pcall
local raw_finish = E.__octane_finish
local setid = E.setthreadidentity
local getid = E.getthreadidentity
local function pack(...) return { n = select("#", ...), ... } end
local function wrap(f)
    return function(...)
        local old = getid and getid()
        if setid then pcall(setid, 8) end
        local r = pack(raw_pcall(f, ...))
        if setid and old then pcall(setid, old) end
        if not r[1] then error(r[2], 0) end
        return unpack(r, 2, r.n)
    end
end
if game_task then
    E.task = setmetatable({}, { __index = game_task })
    if raw_spawn then E.task.spawn = function(f, ...) return raw_spawn(wrap(f), ...) end end
    if raw_defer then E.task.defer = function(f, ...) return raw_defer(wrap(f), ...) end end
    if raw_wait then E.task.wait = raw_wait end
end
if raw_spawn then E.spawn = function(f, ...) return raw_spawn(wrap(f), ...) end end
if raw_defer then E.delay = function(t, f, ...) return raw_defer(wrap(f), ...) end end

-- Async script entry: defer the chunk so it runs on the next scheduler cycle,
-- after the interrupted luaD_call has returned. Running it inside the hook
-- corrupts the pending CallInfo.
if raw_defer then
    E.__run = function(fn, tok)
        raw_defer(function()
            local old = getid and getid()
            if setid then pcall(setid, 8) end
            local ok, res = raw_pcall(fn)
            if setid and old then pcall(setid, old) end
            if raw_finish then raw_finish(ok, res, tok) end
        end)
    end
elseif raw_spawn then
    E.__run = function(fn, tok)
        raw_spawn(function()
            local old = getid and getid()
            if setid then pcall(setid, 8) end
            local ok, res = raw_pcall(fn)
            if setid and old then pcall(setid, old) end
            if raw_finish then raw_finish(ok, res, tok) end
        end)
    end
end

-- ---------- Synapse `syn` library ----------
-- The instance cache is the same table the FindFirstChild hook uses; replacing
-- an entry makes the next lookup of `obj` return `target`.
local protected = shared("__octane_protected", true)
local syn = {
    cache_replace = function(obj, target)
        if not is_instance(obj) or not is_instance(target) then return end
        proxy_of[unproxy(obj)] = make_proxy(unproxy(target))
    end,
    cache_invalidate = function(obj)
        if not is_instance(obj) then return end
        invalid[unproxy(obj)] = true
        proxy_of[unproxy(obj)] = nil
    end,
    is_cached = function(obj)
        return is_instance(obj) and invalid[unproxy(obj)] == nil
    end,
    set_thread_identity = function(n) identity = n; E.setthreadidentity(n) end,
    get_thread_identity = function() return identity end,
    write_clipboard = function(s) E.setclipboard(tostring(s)) end,
    queue_on_teleport = function(code) pcall(E.queue_on_teleport, code) end,
    protect_gui = function(gui)
        if is_instance(gui) then protected[unproxy(gui)] = true end
    end,
    unprotect_gui = function(gui)
        local real = unproxy(gui)
        if not protected[real] then error("gui is not protected", 2) end
        protected[real] = nil
    end,
    is_beta = function() return false end,
    request = E.request,
    secure_call = function(fn, _, ...)
        if type(fn) ~= "function" then error("secure_call: function expected", 2) end
        return fn(...)
    end,
    create_secure_function = function(code) return tostring(code) end,
    run_secure_function = function(code)
        local fn = assert(loadstring(tostring(code), "=secure"))
        return fn()
    end,
}
syn.crypt = crypt
syn.crypto = crypt
syn.websocket = WebSocket
syn.secrun = syn.run_secure_function
E.syn = syn

-- ---------- saveinstance ----------
-- Full-fidelity .rbxlx save for this 2021 client, in the spirit of
-- UniversalSynSaveInstance: every client-visible instance, the properties the
-- 0.463 API dump says load, attributes, tags, decompiled scripts, and smooth
-- terrain. The dump is shipped as octopussy_api.lua next to this file.
local SI_SERVICE_SKIP = {
    CoreGui = true, CorePackages = true, PluginGuiService = true, TestService = true,
    NetworkClient = true, NetworkServer = true, VirtualUser = true,
    VirtualInputManager = true, LogService = true, ScriptContext = true,
    ContentProvider = true, Studio = true, AdService = true, PolicyService = true,
    CoreScriptSyncService = true, MessageBusService = true,
}
local SI_CLASS_SKIP = {
    PlayerGui = true, PlayerScripts = true, PlayerMouse = true, ScreenshotHud = true,
    TouchTransmitter = true, StudioData = true,
}

local function si_clean(s)
    return (tostring(s):gsub("[%z\1-\8\11\12\14-\31\127]", ""))
end

local function si_escape(s)
    s = si_clean(s)
    s = s:gsub("&", "&amp;"):gsub("<", "&lt;"):gsub(">", "&gt;"):gsub('"', "&quot;")
    return s
end

local function si_text(s)
    s = si_clean(s)
    if s:find("]]>", 1, true) then return si_escape(s) end
    return "<![CDATA[" .. s .. "]]>"
end

local function si_num(v, kind)
    if v ~= v or v == math.huge or v == -math.huge then return nil end
    if kind == "int" then return "int", string.format("%d", v) end
    if kind == "int64" then return "int64", string.format("%d", v) end
    if kind == "float" then return "float", string.format("%.9g", v) end
    if kind == "double" then return "double", string.format("%.17g", v) end
    if v == math.floor(v) and math.abs(v) < 2147483648 then
        return "int", string.format("%d", v)
    end
    return "double", string.format("%.17g", v)
end

local function si_ref(name, v, refs)
    local n = refs and refs[v]
    if not n then return nil end
    return '<Ref name="' .. name .. '">RBX' .. n .. "</Ref>"
end

local function si_sequence(v, color)
    local out = {}
    for _, k in ipairs(v.Keypoints) do
        local t, val = k.Time, k.Value
        if t == t and t ~= math.huge and t ~= -math.huge then
            if color then
                out[#out + 1] = string.format("%.9g %.9g %.9g %.9g 0 ", t, val.R, val.G, val.B)
            else
                local env = k.Envelope or 0
                out[#out + 1] = string.format("%.9g %.9g %.9g ", t, val, env)
            end
        end
    end
    if #out == 0 then return nil end
    return table.concat(out)
end

local function si_value(name, v, kind, refs)
    local t = typeof(v)

    if kind == "color3uint8" then
        return string.format('<Color3uint8 name="%s">%d</Color3uint8>', name,
            0xFF000000 + math.floor(v.R * 255 + 0.5) * 65536 +
            math.floor(v.G * 255 + 0.5) * 256 + math.floor(v.B * 255 + 0.5))
    end
    if kind == "Content" or t == "Content" then
        local s = tostring(v)
        if s == "" then return '<Content name="' .. name .. '"><null></null></Content>' end
        return '<Content name="' .. name .. '"><url>' .. si_escape(s) .. "</url></Content>"
    end
    if t == "Instance" then
        return si_ref(name, v, refs)
    elseif t == "string" then
        return '<string name="' .. name .. '">' .. si_escape(v) .. "</string>"
    elseif t == "boolean" then
        return '<bool name="' .. name .. '">' .. (v and "true" or "false") .. "</bool>"
    elseif t == "number" then
        local tag, text = si_num(v, kind)
        if not tag then return nil end
        return "<" .. tag .. ' name="' .. name .. '">' .. text .. "</" .. tag .. ">"
    elseif t == "EnumItem" then
        return '<token name="' .. name .. '">' .. tostring(v.Value) .. "</token>"
    elseif t == "Vector3" then
        return string.format('<Vector3 name="%s"><X>%.9g</X><Y>%.9g</Y><Z>%.9g</Z></Vector3>',
            name, v.X, v.Y, v.Z)
    elseif t == "Vector2" then
        return string.format('<Vector2 name="%s"><X>%.9g</X><Y>%.9g</Y></Vector2>', name, v.X, v.Y)
    elseif t == "Color3" then
        return string.format('<Color3 name="%s"><R>%.9g</R><G>%.9g</G><B>%.9g</B></Color3>',
            name, v.R, v.G, v.B)
    elseif t == "BrickColor" then
        return '<BrickColor name="' .. name .. '">' .. tostring(v.Number) .. "</BrickColor>"
    elseif t == "CFrame" then
        local c = { v:GetComponents() }
        if #c < 12 then return nil end
        return string.format(
            '<CoordinateFrame name="%s"><X>%.9g</X><Y>%.9g</Y><Z>%.9g</Z>' ..
            "<R00>%.9g</R00><R01>%.9g</R01><R02>%.9g</R02>" ..
            "<R10>%.9g</R10><R11>%.9g</R11><R12>%.9g</R12>" ..
            "<R20>%.9g</R20><R21>%.9g</R21><R22>%.9g</R22></CoordinateFrame>",
            name, c[1], c[2], c[3], c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12])
    elseif t == "UDim" then
        return string.format('<UDim name="%s"><S>%.9g</S><O>%d</O></UDim>', name, v.Scale, v.Offset)
    elseif t == "UDim2" then
        return string.format(
            '<UDim2 name="%s"><XS>%.9g</XS><XO>%d</XO><YS>%.9g</YS><YO>%d</YO></UDim2>',
            name, v.X.Scale, v.X.Offset, v.Y.Scale, v.Y.Offset)
    elseif t == "Rect" then
        return string.format('<Rect2D name="%s"><min><X>%.9g</X><Y>%.9g</Y></min>' ..
            "<max><X>%.9g</X><Y>%.9g</Y></max></Rect2D>",
            name, v.Min.X, v.Min.Y, v.Max.X, v.Max.Y)
    elseif t == "NumberRange" then
        return string.format('<NumberRange name="%s">%.9g %.9g</NumberRange>', name, v.Min, v.Max)
    elseif t == "NumberSequence" then
        local s = si_sequence(v, false)
        if not s then return nil end
        return '<NumberSequence name="' .. name .. '">' .. s .. "</NumberSequence>"
    elseif t == "ColorSequence" then
        local s = si_sequence(v, true)
        if not s then return nil end
        return '<ColorSequence name="' .. name .. '">' .. s .. "</ColorSequence>"
    elseif t == "Ray" then
        return string.format('<Ray name="%s"><origin><X>%.9g</X><Y>%.9g</Y><Z>%.9g</Z></origin>' ..
            "<direction><X>%.9g</X><Y>%.9g</Y><Z>%.9g</Z></direction></Ray>",
            name, v.Origin.X, v.Origin.Y, v.Origin.Z,
            v.Direction.X, v.Direction.Y, v.Direction.Z)
    elseif t == "PhysicalProperties" then
        return string.format(
            '<PhysicalProperties name="%s"><CustomPhysics>true</CustomPhysics>' ..
            "<Density>%.9g</Density><Friction>%.9g</Friction><Elasticity>%.9g</Elasticity>" ..
            "<FrictionWeight>%.9g</FrictionWeight><ElasticityWeight>%.9g</ElasticityWeight>" ..
            "</PhysicalProperties>",
            name, v.Density, v.Friction, v.Elasticity, v.FrictionWeight, v.ElasticityWeight)
    elseif t == "BinaryString" then
        local s = tostring(v)
        if s == "" then return nil end
        return '<BinaryString name="' .. name .. '">' .. b64encode(s) .. "</BinaryString>"
    end
    return nil
end

-- XML names that differ from the scriptable property name on this client.
-- The value is {xmlName, valueKind}; valueKind defaults to the dump type.
local SI_ALIAS = {
    BasePart = { Color = { "Color3uint8", "color3uint8" }, Size = { "size" } },
    Part = { Shape = { "shape" } },
    FormFactorPart = { FormFactor = { "formFactorRaw" } },
    Humanoid = { Health = { "Health_XML", "float" } },
    Fire = { Size = { "size_xml", "float" }, Heat = { "heat_xml", "float" } },
    Smoke = {
        Size = { "size_xml", "float" }, Opacity = { "opacity_xml", "float" },
        RiseVelocity = { "riseVelocity_xml", "float" },
    },
    PartOperation = { MeshSize = { "InitialSize" } },
    TrussPart = { Style = { "style" } },
    WeldConstraint = { Part0 = { "Part0Internal" }, Part1 = { "Part1Internal" } },
    BallSocketConstraint = { MaxFrictionTorque = { "MaxFrictionTorqueXml" } },
    DoubleConstrainedValue = { Value = { "value" } },
    IntConstrainedValue = { Value = { "value" } },
    Players = {
        MaxPlayers = { "MaxPlayersInternal" }, PreferredPlayers = { "PreferredPlayersInternal" },
    },
    StarterPlayer = { AvatarJointUpgrade = { "AvatarJointUpgrade_Serialized" } },
}

local SI_TERRAIN_MATERIALS = {
    "Grass", "Slate", "Concrete", "Brick", "Sand", "WoodPlanks", "Rock", "Glacier",
    "Snow", "Sandstone", "Mud", "Basalt", "Ground", "CrackedLava", "Asphalt",
    "Cobblestone", "Ice", "LeafyGrass", "Salt", "Limestone", "Pavement",
}
local SI_TERRAIN_SLOT = {}
do
    local names = { "Air", "Water", "Grass", "Slate", "Concrete", "Brick", "Sand",
        "WoodPlanks", "Rock", "Glacier", "Snow", "Sandstone", "Mud", "Basalt",
        "Ground", "CrackedLava", "Asphalt", "Cobblestone", "Ice", "LeafyGrass",
        "Salt", "Limestone", "Pavement" }
    for i, n in ipairs(names) do
        local m = Enum.Material[n]
        if m then SI_TERRAIN_SLOT[m.Value] = i - 1 end
    end
end

local function si_material_colors(inst)
    local ok, bytes = pcall(function()
        local out = { string.rep("\0", 6) }
        for _, name in ipairs(SI_TERRAIN_MATERIALS) do
            local m = Enum.Material[name]
            if not m then return nil end
            local c = inst:GetMaterialColor(m)
            out[#out + 1] = string.char(
                math.floor(c.R * 255 + 0.5), math.floor(c.G * 255 + 0.5),
                math.floor(c.B * 255 + 0.5))
        end
        return table.concat(out)
    end)
    if ok and bytes then
        return '<BinaryString name="MaterialColors">' .. b64encode(bytes) .. "</BinaryString>"
    end
end

local SI_SPECIAL = {
    Terrain = { MaterialColors = si_material_colors },
}

local si_api_cache
local function si_api()
    if si_api_cache ~= nil then return si_api_cache or nil end
    si_api_cache = false
    local dir = E.__octane_dir
    if not dir then return nil end
    local ok, text = pcall(readfile, dir .. "\\octopussy_api.lua")
    if not ok or type(text) ~= "string" or #text == 0 then return nil end
    local okf, f = pcall(loadstring, text, "=octopussy_api")
    if not okf or type(f) ~= "function" then return nil end
    local okr, tbl = pcall(f)
    if not okr or type(tbl) ~= "table" then return nil end
    si_api_cache = tbl
    return tbl
end

local si_flat, si_lists = {}, {}
local function si_class_info(cls)
    local hit = si_flat[cls]
    if hit then return hit end
    local api = si_api()
    local entry = api and api[cls]
    if not entry then
        hit = { props = {} }
        si_flat[cls] = hit
        return hit
    end
    local props, seen = {}, {}
    local super = entry.super
    if super and super ~= "" then
        for _, p in ipairs(si_class_info(super).props) do
            props[#props + 1] = p
            seen[p[1]] = true
        end
    end
    for _, p in ipairs(entry.props) do
        if not seen[p[1]] then
            props[#props + 1] = p
            seen[p[1]] = true
        end
    end
    hit = { props = props, super = super }
    si_flat[cls] = hit
    return hit
end

local function si_alias(cls, prop)
    local c = cls
    while c do
        local a = SI_ALIAS[c]
        if a and a[prop] then return a[prop] end
        local info = si_class_info(c)
        c = info.super
    end
end

local function si_special_for(cls, prop)
    local c = cls
    while c do
        local s = SI_SPECIAL[c]
        if s and s[prop] then return s[prop] end
        local info = si_class_info(c)
        c = info.super
    end
end

local SI_FALLBACK = {
    "CFrame", "Size", "Color", "Material", "Transparency", "Anchored", "CanCollide",
    "Reflectance", "Massless", "CanTouch", "Shape", "FormFactor", "Gravity",
    "FallenPartsDestroyHeight", "Ambient", "OutdoorAmbient", "Brightness", "ClockTime",
    "FogEnd", "FogStart", "GeographicLatitude", "ExposureCompensation", "Text", "Font",
    "TextSize", "TextColor3", "BackgroundColor3", "BackgroundTransparency", "Visible",
    "Image", "Value", "SoundId", "Volume", "Looped", "Playing", "PlaybackSpeed",
}
local SI_FALLBACK_XML = { Size = "size", Color = "Color3uint8", Shape = "shape", FormFactor = "formFactorRaw" }

local function si_props(inst)
    local cls = inst.ClassName
    local hit = si_lists[cls]
    if hit then return hit end
    local list = {}
    local api = si_api()
    if not api then
        for _, name in ipairs(SI_FALLBACK) do
            local ok, v = pcall(function() return inst[name] end)
            if ok and v ~= nil then
                list[#list + 1] = { name = name, xml = SI_FALLBACK_XML[name] or name, kind = nil }
            end
        end
        si_lists[cls] = list
        return list
    end

    local info = si_class_info(cls)
    for _, p in ipairs(info.props) do
        local name, typ, canSave = p[1], p[2], p[3]
        local special = si_special_for(cls, name)
        local alias = si_alias(cls, name)
        if special then
            list[#list + 1] = { name = name, special = special }
        else
            local xml, kind
            if alias then
                xml, kind = alias[1], alias[2] or typ
            elseif canSave == 1 then
                xml, kind = name, typ
            end
            if xml then
                list[#list + 1] = { name = name, xml = xml, kind = kind }
            end
        end
    end
    si_lists[cls] = list
    return list
end

-- AttributesSerialize, per RobloxAPI/spec.
local function si_attr_value(v)
    local t = typeof(v)
    if t == "string" then
        return 2, string.pack("<I4", #v) .. v
    elseif t == "boolean" then
        return 3, string.char(v and 1 or 0)
    elseif t == "number" then
        if v ~= v or v == math.huge or v == -math.huge then return nil end
        return 6, string.pack("<d", v)
    elseif t == "UDim" then
        return 9, string.pack("<fi4", v.Scale, v.Offset)
    elseif t == "UDim2" then
        return 10, string.pack("<fi4fi4", v.X.Scale, v.X.Offset, v.Y.Scale, v.Y.Offset)
    elseif t == "BrickColor" then
        return 14, string.pack("<I4", v.Number)
    elseif t == "Color3" then
        return 15, string.pack("<fff", v.R, v.G, v.B)
    elseif t == "Vector2" then
        return 16, string.pack("<ff", v.X, v.Y)
    elseif t == "Vector3" then
        return 17, string.pack("<fff", v.X, v.Y, v.Z)
    elseif t == "CFrame" then
        local c = { v:GetComponents() }
        if #c < 12 then return nil end
        return 20, string.pack("<fffBfffffffff", c[1], c[2], c[3], 0,
            c[4], c[5], c[6], c[7], c[8], c[9], c[10], c[11], c[12])
    elseif t == "NumberSequence" then
        local out = { string.pack("<I4", #v.Keypoints) }
        for _, k in ipairs(v.Keypoints) do
            out[#out + 1] = string.pack("<fff", k.Envelope, k.Time, k.Value)
        end
        return 23, table.concat(out)
    elseif t == "ColorSequence" then
        local out = { string.pack("<I4", #v.Keypoints) }
        for _, k in ipairs(v.Keypoints) do
            out[#out + 1] = string.pack("<fff", k.Envelope, k.Time, 0)
            out[#out + 1] = string.pack("<fff", k.Value.R, k.Value.G, k.Value.B)
        end
        return 25, table.concat(out)
    elseif t == "NumberRange" then
        return 27, string.pack("<ff", v.Min, v.Max)
    elseif t == "Rect" then
        return 28, string.pack("<ffff", v.Min.X, v.Min.Y, v.Max.X, v.Max.Y)
    end
end

local function si_attributes(inst)
    local ok, attrs = pcall(function() return inst:GetAttributes() end)
    if not ok or type(attrs) ~= "table" or next(attrs) == nil then return nil end
    local names = {}
    for k in pairs(attrs) do names[#names + 1] = k end
    table.sort(names)
    local entries = {}
    for _, k in ipairs(names) do
        local tid, data = si_attr_value(attrs[k])
        if tid then
            entries[#entries + 1] = string.pack("<I4", #k) .. k .. string.char(tid) .. data
        end
    end
    if #entries == 0 then return nil end
    return string.pack("<I4", #entries) .. table.concat(entries)
end

local function si_tags(inst)
    local ok, tags = pcall(function()
        return game:GetService("CollectionService"):GetTags(inst)
    end)
    if not ok or type(tags) ~= "table" or #tags == 0 then return nil end
    return table.concat(tags, "\0")
end

-- SmoothGrid v1 (version byte 1, chunk exponent 6). Terrain is read in
-- 256-stud chunks and RLE-encoded in the native X-fastest/Z/Y order.
local function si_smoothgrid()
    local terrain = workspace.Terrain
    local ok, size = pcall(function() return terrain.Size end)
    if not ok or typeof(size) ~= "Vector3" then return nil end
    local minX = math.floor((-size.X * 0.5) / 4) * 4
    local maxX = math.ceil((size.X * 0.5) / 4) * 4
    local minY = math.floor((-size.Y * 0.5) / 4) * 4
    local maxY = math.ceil((size.Y * 0.5) / 4) * 4
    local minZ = math.floor((-size.Z * 0.5) / 4) * 4
    local maxZ = math.ceil((size.Z * 0.5) / 4) * 4
    if maxX - minX > 4096 or maxY - minY > 4096 or maxZ - minZ > 4096 then
        return nil, "terrain extent too large"
    end

    local chunks, chunkN, cells = {}, 0, 0
    local prevX, prevY, prevZ = 0, 0, 0
    local y = minY
    while y < maxY do
        local z = minZ
        while z < maxZ do
            local x = minX
            while x < maxX do
                local okr, materials, occupancies = pcall(terrain.ReadVoxels, terrain,
                    Region3.new(Vector3.new(x, y, z), Vector3.new(x + 256, y + 256, z + 256)), 4)
                if okr and type(materials) == "table" and #materials > 0 then
                    local recs = {}
                    local rm, ro, rn = -1, 0, 0
                    local any = false
                    local function flush()
                        if rn <= 0 then return end
                        local h = rm
                        local extra = ""
                        if ro ~= 255 then h = h + 64; extra = string.char(ro) end
                        if rn > 1 then h = h + 128; extra = extra .. string.char(rn - 1) end
                        recs[#recs + 1] = string.char(h) .. extra
                    end
                    local nx, ny, nz = #materials, #materials[1], #materials[1][1]
                    for yi = 1, ny do
                        for zi = 1, nz do
                            for xi = 1, nx do
                                local m = materials[xi][yi][zi]
                                local mat = SI_TERRAIN_SLOT[m.Value]
                                if not mat then mat = 2 end
                                local occ = occupancies[xi][yi][zi]
                                local ob
                                if mat == 0 or occ <= 0 then
                                    ob = 0
                                else
                                    ob = math.floor(occ * 256 - 0.5)
                                    if ob < 0 then ob = 0 elseif ob > 255 then ob = 255 end
                                end
                                if mat ~= 0 then any = true end
                                if mat == rm and ob == ro and rn < 256 then
                                    rn = rn + 1
                                else
                                    flush()
                                    rm, ro, rn = mat, ob, 1
                                end
                            end
                        end
                    end
                    flush()
                    if any then
                        local cx = math.floor((x / 4) / 64)
                        local cy = math.floor((y / 4) / 64)
                        local cz = math.floor((z / 4) / 64)
                        local dx, dy, dz = cx - prevX, cy - prevY, cz - prevZ
                        local header = {}
                        for _, sh in ipairs({ 24, 16, 8, 0 }) do
                            header[#header + 1] = string.char(
                                bit32.band(bit32.rshift(dx, sh), 255),
                                bit32.band(bit32.rshift(dy, sh), 255),
                                bit32.band(bit32.rshift(dz, sh), 255))
                        end
                        prevX, prevY, prevZ = cx, cy, cz
                        chunks[#chunks + 1] = table.concat(header) .. table.concat(recs)
                        chunkN = chunkN + 1
                        cells = cells + nx * ny * nz
                    end
                end
                x = x + 256
            end
            z = z + 256
        end
        y = y + 256
        task.wait()
    end
    if chunkN == 0 then return nil end
    return string.char(1, 6) .. table.concat(chunks), chunkN, cells
end

local function saveinstance(opts)
    if type(opts) == "string" then opts = { FileName = opts } end
    opts = opts or {}

    local root = opts.Root or opts.Object or game
    if not is_instance(root) then return nil, "root must be an Instance" end

    local function run()
        local t0 = tick()
        local list = { root }
        if root ~= game then
            local okd, desc = pcall(function() return root:GetDescendants() end)
            if okd then for i = 1, #desc do list[#list + 1] = desc[i] end end
        else
            local okd, desc = pcall(function() return game:GetDescendants() end)
            if okd then for i = 1, #desc do list[#list + 1] = desc[i] end end
        end

        local keep, kids, refs, count = {}, {}, {}, 0
        for _, inst in ipairs(list) do
            local parent = inst.Parent
            local cls = inst.ClassName
            local skip = SI_SERVICE_SKIP[cls] or SI_CLASS_SKIP[cls]
            if inst == root then
                skip = false
            elseif parent and keep[parent] == false then
                skip = true
            end
            if skip then
                keep[inst] = false
            else
                keep[inst] = true
                count = count + 1
                refs[inst] = count
                if parent then
                    local k = kids[parent]
                    if not k then k = {}; kids[parent] = k end
                    k[#k + 1] = inst
                end
            end
        end

        local decompile = opts.Decompile ~= false and opts.NoScripts ~= true and opts.noscripts ~= true

        if not isfolder("saveinstance") then pcall(makefolder, "saveinstance") end
        local gameId = 0
        pcall(function() gameId = game.GameId end)
        local name = opts.FileName or opts.name
        if not name then
            name = string.format("%s_%s.rbxlx", tostring(gameId), os.date("%Y%m%d_%H%M%S"))
        end
        name = tostring(name):gsub("[^%w%._%-]", "_")
        if not name:match("%.rbxlx$") then name = name .. ".rbxlx" end
        local path = "saveinstance/" .. name

        local buf, blen, wrote, bytes = {}, 0, false, 0
        local function flush()
            if blen == 0 then return end
            local chunk = table.concat(buf)
            if wrote then appendfile(path, chunk) else writefile(path, chunk); wrote = true end
            bytes = bytes + #chunk
            buf, blen = {}, 0
        end
        local function emit(s)
            buf[#buf + 1] = s
            blen = blen + #s
            if blen >= 1048576 then flush() end
        end

        -- every script by default; DecompileTimeout limits the wall clock
        local budget = tonumber(opts.DecompileTimeout or opts.timeout) or math.huge
        local dec = {
            deadline = budget < 0 and math.huge or (tick() + budget),
            used = 0, tried = 0, skipped = 0,
        }
        local maxTerrain = opts.Terrain ~= false
        local terrainGrid, terrainChunks, terrainCells

        local serialized = 0
        local function serialize(inst, depth)
            serialized = serialized + 1
            if serialized % 200 == 0 then
                task.wait()
                if serialized % 2000 == 0 then
                    print(string.format("saveinstance: %d/%d", serialized, count))
                end
            end
            emit('<Item class="' .. si_escape(inst.ClassName) .. '" referent="RBX' .. refs[inst] .. '"><Properties>')
            emit('<string name="Name">' .. si_escape(inst.Name) .. "</string>")

            local props = si_props(inst)
            for _, p in ipairs(props) do
                if p.special then
                    local ok, xml = pcall(p.special, inst)
                    if ok and type(xml) == "string" and #xml > 0 then emit(xml) end
                else
                    local ok, v = pcall(function() return inst[p.name] end)
                    if ok and v ~= nil then
                        local xml = si_value(p.xml, v, p.kind, refs)
                        if xml then emit(xml) end
                    end
                end
            end

            if opts.Attributes ~= false then
                local attrs = si_attributes(inst)
                if attrs then
                    emit('<BinaryString name="AttributesSerialize">' .. b64encode(attrs) .. "</BinaryString>")
                end
            end
            if opts.Tags ~= false then
                local tags = si_tags(inst)
                if tags then
                    emit('<BinaryString name="Tags">' .. b64encode(tags) .. "</BinaryString>")
                end
            end

            if inst:IsA("LuaSourceContainer") then
                local source
                if not decompile then
                    source = "-- [scripts skipped]"
                elseif tick() > dec.deadline then
                    dec.skipped = dec.skipped + 1
                    source = "-- [not decompiled: saveinstance decompile budget]"
                else
                    dec.tried = dec.tried + 1
                    local ok, text = pcall(E.decompile, inst, false)
                    if ok and type(text) == "string" and #text > 0 then
                        source = text
                        -- markers start with "--"; only real code counts
                        if text:sub(1, 2) ~= "--" then dec.used = dec.used + 1 end
                    else
                        source = "-- [decompile failed: " .. tostring(text or "unknown") .. "]"
                    end
                end
                if source then
                    emit('<ProtectedString name="Source">' .. si_text(source) .. "</ProtectedString>")
                end
            end

            if maxTerrain and inst:IsA("Terrain") and terrainGrid == nil and terrainChunks == nil then
                local grid, chunks, cells = si_smoothgrid()
                terrainGrid, terrainChunks, terrainCells = grid or false, chunks or 0, cells or 0
                if grid then
                    print(string.format("saveinstance: terrain %d chunks, %d cells", chunks, cells))
                end
            end
            if inst:IsA("Terrain") and terrainGrid then
                emit('<BinaryString name="SmoothGrid">' .. b64encode(terrainGrid) .. "</BinaryString>")
            end

            emit("</Properties>")
            local children = kids[inst]
            if children then
                for _, child in ipairs(children) do serialize(child, depth + 1) end
            end
            emit("</Item>")
        end

        emit('<roblox xmlns:xmime="http://www.w3.org/2005/05/xmlmime" ' ..
             'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ' ..
             'xsi:noNamespaceSchemaLocation="http://www.roblox.com/roblox.xsd" version="4">\n')
        emit("<External>null</External><External>nil</External>\n")

        print(string.format("saveinstance: %d instances, scripts=%s, terrain=%s, attributes/tags=%s",
            count, tostring(decompile), tostring(maxTerrain),
            tostring(opts.Attributes ~= false or opts.Tags ~= false)))

        if root == game then
            for _, service in ipairs(kids[game] or {}) do serialize(service, 0) end
        else
            serialize(root, 0)
        end
        emit("</roblox>\n")
        flush()

        if decompile then
            print(string.format("saveinstance: decompiled %d of %d scripts tried (%d skipped)",
                dec.used, dec.tried, dec.skipped))
        end
        print(string.format("saveinstance: wrote %s (%d bytes, %d instances, %.1fs)",
            path, bytes, count, tick() - t0))
        return path, count
    end

    local dsl = E.__decompiler
    if decompile and dsl and dsl.lock then pcall(dsl.lock) end
    local ok, a, b = pcall(run)
    if decompile and dsl and dsl.unlock then pcall(dsl.unlock) end
    if not ok then
        print("saveinstance error: " .. tostring(a))
        return nil, tostring(a)
    end
    return a, b
end
E.saveinstance = saveinstance
def("saveinstance", saveinstance)
def("synsaveinstance", saveinstance)

-- ---------- aliases ----------
def("base64_encode", crypt.base64encode)
def("base64_decode", crypt.base64decode)
def("http", { request = E.request })
def("dumpstring", function(s) return tostring(s) end)

return E
