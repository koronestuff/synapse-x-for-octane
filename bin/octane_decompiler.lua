-- octopussy Luau bytecode decompiler.
-- Loaded by octane_bootstrap.lua: returns function(api) -> decompiler table.
-- api = { pfield, kv, child, protoaddr, readmem }
local function build(api)
    local NAMES = {
        "NOP", "BREAK", "LOADNIL", "LOADB", "LOADN", "LOADK", "MOVE", "GETGLOBAL",
        "SETGLOBAL", "GETUPVAL", "SETUPVAL", "CLOSEUPVALS", "GETIMPORT", "GETTABLE",
        "SETTABLE", "GETTABLEKS", "SETTABLEKS", "GETTABLEN", "SETTABLEN", "NEWCLOSURE",
        "NAMECALL", "CALL", "RETURN", "JUMP", "JUMPBACK", "JUMPIF", "JUMPIFNOT",
        "JUMPIFEQ", "JUMPIFLE", "JUMPIFLT", "JUMPIFNOTEQ", "JUMPIFNOTLE", "JUMPIFNOTLT",
        "ADD", "SUB", "MUL", "DIV", "MOD", "POW", "ADDK", "SUBK", "MULK", "DIVK",
        "MODK", "POWK", "AND", "OR", "ANDK", "ORK", "CONCAT", "NOT", "MINUS", "LENGTH",
        "NEWTABLE", "DUPTABLE", "SETLIST", "FORNPREP", "FORNLOOP", "FORGLOOP",
        "FORGPREP_INEXT", "FORGLOOP_INEXT", "FORGPREP_NEXT", "FORGLOOP_NEXT",
        "GETVARARGS", "DUPCLOSURE", "PREPVARARGS", "LOADKX", "JUMPX", "FASTCALL",
        "COVERAGE", "CAPTURE", "JUMPIFEQK", "JUMPIFNOTEQK", "FASTCALL1", "FASTCALL2",
        "FASTCALL2K",
    }
    local AUX = {
        [7] = true, [8] = true, [12] = true, [15] = true, [16] = true, [20] = true,
        [27] = true, [28] = true, [29] = true, [30] = true, [31] = true, [32] = true,
        [53] = true, [55] = true, [58] = true, [66] = true, [71] = true, [72] = true,
        [74] = true, [75] = true,
    }
    local CMP = {
        [27] = "==", [28] = "<=", [29] = "<", [30] = "~=", [31] = ">", [32] = ">=",
        [71] = "==", [72] = "~=",
    }
    local ARITH = {
        [33] = "+", [34] = "-", [35] = "*", [36] = "/", [37] = "%", [38] = "^",
        [39] = "+", [40] = "-", [41] = "*", [42] = "/", [43] = "%", [44] = "^",
    }
    local PREC = {
        ["or"] = 20, ["and"] = 30, ["=="] = 40, ["~="] = 40, ["<"] = 40, [">"] = 40,
        ["<="] = 40, [">="] = 40, [".."] = 55, ["+"] = 60, ["-"] = 60, ["*"] = 70,
        ["/"] = 70, ["%"] = 70, ["^"] = 75, ["not"] = 80, ["-u"] = 80, ["#"] = 80,
    }

    local function fmtNum(v)
        if v ~= v then return "(0/0)" end
        if v == math.huge then return "math.huge" end
        if v == -math.huge then return "-math.huge" end
        if v == math.floor(v) and math.abs(v) < 1e15 then
            return string.format("%d", v)
        end
        local s = tostring(v)
        if not s:find("[.eE]") then s = s .. ".0" end
        return s
    end

    local function fmtStr(s)
        local q = string.format("%q", s)
        if #q > 400 then
            q = string.format("%q", s:sub(1, 300)):sub(1, -2) .. "...\""
        end
        return q
    end

    local function isIdent(s)
        return type(s) == "string" and s:match("^[%a_][%w_]*$") ~= nil
    end

    local function isKeyword(s)
        return s == "and" or s == "break" or s == "do" or s == "else" or s == "elseif"
            or s == "end" or s == "false" or s == "for" or s == "function" or s == "if"
            or s == "in" or s == "local" or s == "nil" or s == "not" or s == "or"
            or s == "repeat" or s == "return" or s == "then" or s == "true"
            or s == "until" or s == "while"
    end

    local function atom(t)
        return { t = t, p = 100 }
    end

    local function wrap(e, minp, right)
        if not e then return "nil" end
        if e.p < minp or (right and e.p == minp) then return "(" .. e.t .. ")" end
        return e.t
    end

    -- a literal is not a legal prefix expression ("nil:Connect()" does not parse)
    local function isLiteralText(t)
        return t == "nil" or t == "true" or t == "false" or t == "..."
            or t:match("^%-?%d") ~= nil
            or t:sub(1, 1) == '"' or t:sub(1, 1) == "'"
            or t:sub(1, 1) == "{" or t:sub(1, 8) == "function"
    end

    local function prefixOf(e)
        local t = wrap(e, 90)
        if isLiteralText(t) then return "(" .. t .. ")" end
        return t
    end

    local function bin(op, a, b)
        local p = PREC[op] or 60
        local left = wrap(a, p)
        local right = wrap(b, p, true)
        return { t = left .. " " .. op .. " " .. right, p = p }
    end

    local function un(op, a)
        local p = PREC[op] or 80
        local v = a
        if op == "-u" then
            return { t = "-" .. wrap(a, 80, true), p = 80 }
        end
        return { t = op .. " " .. wrap(a, p, true), p = p }
    end

    local function validProto(addr)
        return type(addr) == "number" and addr > 0
    end

    -- ---------- proto loading ----------
    local function loadProto(addr)
        if not validProto(addr) then return nil end
        local f = { api.pfield(addr) }
        if not f[3] or f[3] < 1 then return nil end
        local p = {
            addr = addr,
            source = f[1], debugname = f[2],
            sizecode = f[3], sizek = f[4], sizep = f[5],
            numparams = f[6] or 0, isvararg = f[7] or 0, stacksize = f[8] or 0,
            nups = f[9] or 0, sizelocvars = f[10] or 0, sizeupvalues = f[11] or 0,
            codeptr = f[12], kptr = f[13], parr = f[14],
            sizelineinfo = f[17] or 0,
        }
        -- readmem caps a single read at 64 KB and at the end of the region,
        -- so long protos need the whole code array stitched from chunks
        local need = p.sizecode * 4
        local parts, got = {}, 0
        while p.codeptr and got < need do
            local chunk = api.readmem(p.codeptr + got, need - got)
            if not chunk or #chunk == 0 then break end
            parts[#parts + 1] = chunk
            got = got + #chunk
        end
        if got < need then return nil end
        local raw = table.concat(parts)
        p.words = {}
        for i = 0, p.sizecode - 1 do
            local b1, b2, b3, b4 = raw:byte(i * 4 + 1, i * 4 + 4)
            p.words[i] = b1 + b2 * 256 + b3 * 65536 + b4 * 16777216
        end
        p.ins = {}
        p.bypc = {}
        p.order = {}
        local i = 0
        while i < p.sizecode do
            local w = p.words[i]
            local b1 = w % 256
            local op = (b1 * 203) % 256
            local A = math.floor(w / 256) % 256
            local B = math.floor(w / 65536) % 256
            local C = math.floor(w / 16777216) % 256
            local D = math.floor(w / 65536) % 65536
            if D >= 32768 then D = D - 65536 end
            local E = math.floor(w / 256) % 16777216
            if E >= 8388608 then E = E - 16777216 end
            local size = AUX[op] and 2 or 1
            local aux = nil
            if size == 2 and i + 1 < p.sizecode then aux = p.words[i + 1] end
            local ins = {
                pc = i, op = op, name = NAMES[op + 1] or ("OP" .. op),
                A = A, B = B, C = C, D = D, E = E, aux = aux, size = size,
            }
            p.ins[#p.ins + 1] = ins
            p.bypc[i] = ins
            p.order[#p.order + 1] = ins
            i = i + size
        end
        return p
    end

    local function nextpc(ins) return ins.pc + ins.size end

    local function targetOf(ins)
        local op = ins.op
        if op == 23 or op == 24 or op == 25 or op == 26 then return ins.pc + 1 + ins.D end
        if op >= 27 and op <= 32 then return ins.pc + 1 + ins.D end
        if op == 56 then return ins.pc + 1 + ins.D end
        if op == 58 or op == 60 or op == 62 then return ins.pc + 1 + ins.D end
        if op == 67 then return ins.pc + 1 + ins.E end
        if op == 71 or op == 72 then return ins.pc + 1 + ins.D end
        return nil
    end

    local function isCond(ins)
        local op = ins.op
        return op == 25 or op == 26 or (op >= 27 and op <= 32) or op == 71 or op == 72
    end

    local function isJump(ins)
        return ins.op == 23 or ins.op == 24 or ins.op == 67
    end

    -- register read/write sets (conservative)
    local function analyze(ins)
        local op = ins.op
        local A, B, C = ins.A, ins.B, ins.C
        local r, w = {}, {}
        local function rd(x) r[#r + 1] = x end
        local function wr(x) w[#w + 1] = x end
        if op == 2 or op == 3 or op == 4 or op == 5 or op == 7 or op == 9 or op == 12
            or op == 19 or op == 53 or op == 54 or op == 63 or op == 64 or op == 66 then
            wr(A)
        elseif op == 6 then rd(B); wr(A)
        elseif op == 8 then rd(A)
        elseif op == 10 then rd(A)
        elseif op == 13 then rd(B); rd(C); wr(A)
        elseif op == 14 then rd(A); rd(B); rd(C)
        elseif op == 15 then rd(B); wr(A)
        elseif op == 16 then rd(A); rd(B)
        elseif op == 17 then rd(B); wr(A)
        elseif op == 18 then rd(A); rd(B)
        elseif op == 20 then rd(B); wr(A); wr(A + 1)
        elseif op == 21 then
            rd(A)
            if B == 0 then
                for x = A + 1, A + (ins.stacksize or 8) do rd(x) end
            else
                for x = A + 1, A + B - 1 do rd(x) end
            end
            -- C == 1 returns nothing, C == 0 has an unknown count; counting
            -- the latter would inflate unrelated registers
            if C ~= 1 then wr(A) end
            if C > 1 then
                for x = A + 1, A + C - 2 do wr(x) end
            end
        elseif op == 22 then
            if B == 0 then
                for x = A, A + (ins.stacksize or 8) do rd(x) end
            else
                for x = A, A + B - 2 do rd(x) end
            end
        elseif op == 25 or op == 26 then rd(A)
        elseif op >= 27 and op <= 32 then rd(A); if ins.aux then rd(ins.aux % 256) end
        elseif op >= 33 and op <= 38 then rd(B); rd(C); wr(A)
        elseif op >= 39 and op <= 44 then rd(B); wr(A)
        elseif op == 45 or op == 46 then rd(B); rd(C); wr(A)
        elseif op == 47 or op == 48 then rd(B); wr(A)
        elseif op == 49 then for x = B, C do rd(x) end; wr(A)
        elseif op == 50 or op == 51 or op == 52 then rd(B); wr(A)
        elseif op == 55 then
            rd(A)
            if C == 0 then for x = B, B + (ins.stacksize or 8) do rd(x) end
            else for x = B, B + C - 2 do rd(x) end end
        elseif op == 56 then rd(A); rd(A + 1); rd(A + 2)
        elseif op == 57 then rd(A); rd(A + 1); rd(A + 2); wr(A + 2)
        elseif op == 58 or op == 59 or op == 61 then
            rd(A); rd(A + 1); rd(A + 2)
            local n = (op == 58 and ins.aux) or 2
            for x = A + 3, A + 2 + n do wr(x) end
        elseif op == 60 or op == 62 then rd(A); rd(A + 1); rd(A + 2); wr(A + 3); wr(A + 4)
        elseif op == 71 or op == 72 then rd(A)
        elseif op == 73 then rd(B)
        elseif op == 74 then rd(B); if ins.aux then rd(ins.aux % 256) end
        elseif op == 75 then rd(B)
        elseif op == 70 then
            if A == 0 or A == 1 then rd(B) end
        end
        return r, w
    end

    -- ---------- decompiler state ----------
    local Decompiler = {}
    Decompiler.__index = Decompiler

    local function newDecompiler(addr, depth, seen, ups)
        local p = loadProto(addr)
        if not p then return nil end
        local self = setmetatable({}, Decompiler)
        self.p = p
        self.api = api
        self.depth = depth or 0
        self.seen = seen or {}
        self.ups = ups or {}
        self.out = {}
        self.level = 0
        self.regs = {}
        self.declared = {}
        self.method = {}
        self.writeCount = {}
        self.loops = {}
        self.pendingIter = nil
        self.lastMulti = nil
        self.defer = false
        self.lines = 0
        self.maxLines = 5000
        for r = 0, math.max(p.stacksize or 0, 8) do
            self.regs[r] = atom("v" .. r)
            self.writeCount[r] = 0
        end
        for r = 0, p.numparams - 1 do self.declared[r] = true end
        self:scanWrites()
        self:scanLoops()
        return self
    end

    function Decompiler:line(s)
        if self.lines >= self.maxLines then return end
        if self.level > 30 then return end -- runaway nesting, do not emit
        self.lines = self.lines + 1
        local pad = string.rep("    ", self.level)
        -- nested function bodies arrive as one multi-line string; keep them
        -- aligned with the statement they are embedded in
        self.out[#self.out + 1] = pad .. (s:gsub("\n", "\n" .. pad))
    end

    function Decompiler:raw(s)
        if self.lines >= self.maxLines then return end
        self.lines = self.lines + 1
        self.out[#self.out + 1] = s
    end

    function Decompiler:stmt(s)
        self:line(s)
    end

    function Decompiler:scanWrites()
        for _, ins in ipairs(self.p.order) do
            if ins.op ~= 57 then -- FORNLOOP bump is loop bookkeeping, not a value write
                local _, w = analyze(ins)
                for _, r in ipairs(w) do
                    self.writeCount[r] = (self.writeCount[r] or 0) + 1
                end
            end
        end
    end

    function Decompiler:scanLoops()
        local p = self.p
        -- numeric for
        for _, ins in ipairs(p.order) do
            if ins.op == 56 then
                local exit = targetOf(ins)
                if exit and exit > ins.pc then
                    local loopIns = nil
                    for k = #p.order, 1, -1 do
                        local q = p.order[k]
                        if q.pc > ins.pc and q.pc < exit and q.op == 57 and q.A == ins.A then
                            loopIns = q
                            break
                        end
                    end
                    if loopIns then
                        self.loops[ins.pc] = {
                            kind = "fornum", prep = ins, loop = loopIns,
                            exit = exit, a = ins.A,
                        }
                    end
                end
            end
        end
        -- generic for
        for _, ins in ipairs(p.order) do
            if ins.op == 58 or ins.op == 60 or ins.op == 62 then
                local exit = ins.pc + ins.size
                local jump = nil
                for k = #p.order, 1, -1 do
                    local q = p.order[k]
                    if q.pc < ins.pc and isJump(q) and targetOf(q) == ins.pc then
                        jump = q
                        break
                    end
                end
                if jump then
                    self.loops[jump.pc] = {
                        kind = "forgen", jump = jump, loop = ins,
                        exit = exit, a = ins.A,
                        count = (ins.op == 58 and ins.aux) or 2,
                    }
                    -- the iterator call's results are the loop triple; do not
                    -- let them materialise the values feeding the call
                    local call = p.bypc[jump.pc - 1]
                    if call and call.op == 21 then
                        local A, C = call.A, call.C
                        for x = A, math.max(A, A + (C > 1 and C - 2 or 0)) do
                            if (self.writeCount[x] or 0) > 0 then
                                self.writeCount[x] = self.writeCount[x] - 1
                            end
                        end
                    end
                end
            end
        end
        -- generic for emitted as FORGPREP_NEXT/INEXT + FORGLOOP_NEXT/INEXT:
        -- the prep jumps straight to the loop instruction, so there is no
        -- forward JUMP to key the loop off of
        for _, ins in ipairs(p.order) do
            if ins.op == 61 or ins.op == 59 then
                local loop = p.bypc[ins.pc + 1 + (ins.D or 0)]
                if loop and (loop.op == 62 or loop.op == 60) and loop.A == ins.A then
                    self.loops[ins.pc] = {
                        kind = "forgen", prep = ins, loop = loop,
                        exit = nextpc(loop), a = ins.A, count = 2,
                    }
                end
            end
        end
        -- while / repeat: an unconditional jump backwards closes the loop
        for _, ins in ipairs(p.order) do
            if isJump(ins) then
                local t = targetOf(ins)
                if t and t < ins.pc then
                    local cs = t
                    local condIns = nil
                    for k = #p.order, 1, -1 do
                        local q = p.order[k]
                        if q.pc >= cs and q.pc < ins.pc and isCond(q) then
                            local qt = targetOf(q)
                            if qt and qt > ins.pc then condIns = q; break end
                        end
                    end
                    if condIns and not self.loops[cs] then
                        local exit = targetOf(condIns)
                        -- repeat: the exit conditional is the last thing in the
                        -- body, so the back jump follows it directly
                        local after = nextpc(condIns)
                        local nxt = p.bypc[after]
                        if nxt and nxt.op == 11 then -- CLOSEUPVALS
                            after = nextpc(nxt)
                        end
                        if after == ins.pc then
                            self.loops[cs] = {
                                kind = "repeat", cond = condIns, cs = cs,
                                bodyStart = cs, bodyEnd = condIns.pc,
                                exit = exit,
                            }
                        else
                            self.loops[cs] = {
                                kind = "while", cond = condIns, cs = cs,
                                bodyStart = nextpc(condIns), bodyEnd = ins.pc,
                                exit = exit,
                            }
                        end
                    end
                end
            end
        end
        -- conditional backward jump: repeat in newer codegen
        for _, ins in ipairs(p.order) do
            if isCond(ins) then
                local t = targetOf(ins)
                if t and t < ins.pc and not self.loops[t] then
                    self.loops[t] = {
                        kind = "repeat2", cond = ins, cs = t,
                        bodyStart = t, bodyEnd = ins.pc,
                        exit = nextpc(ins),
                    }
                end
            end
        end
    end

    -- ---------- constants and values ----------
    function Decompiler:upName(i)
        -- nested functions are re-rendered with their capture source names so
        -- the result is still valid Lua instead of referring to "up0". Captures
        -- of a nil/keyword/expression register must not become identifiers.
        local n = self.ups[i]
        if n and isIdent(n) and not isKeyword(n) then return n end
        return "up" .. i
    end

    function Decompiler:const(i)
        if not i or i < 0 or i >= self.p.sizek then return atom("nil") end
        local v = self.api.kv(self.p.addr, i)
        local tv = type(v)
        if tv == "nil" then return atom("nil") end
        if tv == "boolean" then return atom(tostring(v)) end
        if tv == "number" then return atom(fmtNum(v)) end
        if tv == "string" then return atom(fmtStr(v)) end
        if tv == "function" then
            local pa = self.api.protoaddr and self.api.protoaddr(v)
            if pa and pa > 0 and self.depth < 12 and not self.seen[pa] then
                local text = self:subFunction(pa)
                if text then return { t = text, p = 90 } end
            end
            return { t = "function() end", p = 90 }
        end
        if tv == "table" then
            return { t = self:tableText(v, 0), p = 90 }
        end
        return { t = tostring(v), p = 100 }
    end

    function Decompiler:constKey(i)
        local v = self.api.kv(self.p.addr, i)
        if type(v) == "string" then return v end
        if type(v) == "number" then return fmtNum(v) end
        return nil
    end

    function Decompiler:tableText(tbl, depth)
        if type(tbl) ~= "table" then return "{}" end
        local parts = {}
        local n = 0
        local ok = pcall(function()
            for k, v in pairs(tbl) do
                n = n + 1
                if n > 24 then parts[#parts + 1] = "..."; break end
                local kt
                if type(k) == "string" and isIdent(k) and not isKeyword(k) then
                    kt = k .. " = "
                elseif type(k) == "number" then
                    kt = "[" .. fmtNum(k) .. "] = "
                elseif type(k) == "string" then
                    kt = "[" .. fmtStr(k) .. "] = "
                else
                    kt = "[?] = "
                end
                local vt
                if type(v) == "string" then vt = fmtStr(v)
                elseif type(v) == "number" then vt = fmtNum(v)
                elseif type(v) == "boolean" or v == nil then vt = tostring(v)
                elseif type(v) == "table" and depth < 3 then vt = self:tableText(v, depth + 1)
                elseif type(v) == "function" then
                    local pa = self.api.protoaddr and self.api.protoaddr(v)
                    if pa and pa > 0 and depth < 1 and self.depth < 10 and not self.seen[pa] then
                        vt = self:subFunction(pa) or "function() end"
                    else
                        vt = "function() end"
                    end
                else vt = "nil" end
                parts[#parts + 1] = kt .. vt
            end
        end)
        if not ok then return "{}" end
        return "{" .. table.concat(parts, ", ") .. "}"
    end

    function Decompiler:subFunction(addr, ups)
        if self.depth >= 14 then return nil end
        if self.seen[addr] then return nil end
        self.seen[addr] = true
        local d = newDecompiler(addr, self.depth + 1, self.seen, ups)
        if not d then self.seen[addr] = nil; return nil end
        local ok, text = pcall(d.run, d)
        self.seen[addr] = nil
        -- one bad child must not throw away the rest of the parent
        if not ok then return "function() end" end
        return text
    end

    function Decompiler:assign(r, expr, forceMaterial)
        if not expr then expr = atom("nil") end
        if self.defer then
            -- evaluating a loop condition's setup without emitting it; the
            -- value is folded straight into the predicate
            self.regs[r] = expr
            return
        end
        local mat = forceMaterial or (self.writeCount[r] or 0) > 1 or expr.p < 90
        if expr.impure then mat = true end
        local name = "v" .. r
        if mat then
            if self.declared[r] then
                self:stmt(name .. " = " .. expr.t)
            else
                self:stmt("local " .. name .. " = " .. expr.t)
                self.declared[r] = true
            end
            self.regs[r] = atom(name)
        else
            self.regs[r] = expr
        end
    end

    function Decompiler:materializeMultiline(prefix, text)
        local first = true
        for ln in (text .. "\n"):gmatch("(.-)\n") do
            if first then
                self:stmt(prefix .. ln)
                first = false
            else
                self:stmt(ln)
            end
        end
    end

    -- ---------- emit helpers ----------
    function Decompiler:emitValue(ins)
        local op, A, B, C = ins.op, ins.A, ins.B, ins.C
        if op ~= 63 then self.lastMulti = nil end
        if op == 4 then
            self:assign(A, atom(fmtNum(ins.D)))
        elseif op == 5 then
            self:assign(A, self:const(ins.D))
        elseif op == 66 then
            self:assign(A, self:const(ins.aux or 0))
        elseif op == 3 then
            self:assign(A, atom(ins.B ~= 0 and "true" or "false"))
        elseif op == 2 then
            self:assign(A, atom("nil"))
        elseif op == 6 then
            self:assign(A, self.regs[B] or atom("v" .. B))
        elseif op == 7 then
            local name = self:constKey(ins.aux or 0) or "?"
            if isIdent(name) and not isKeyword(name) then
                self:assign(A, atom(name))
            else
                self:assign(A, { t = "_G[" .. fmtStr(name) .. "]", p = 90 })
            end
        elseif op == 9 then
            self:assign(A, atom(self:upName(B)))
        elseif op == 12 then
            local aux = ins.aux or 0
            -- iid: count in the top 2 bits, ids packed from the high slot
            local count = math.floor(aux / 1073741824)
            if count == 0 then count = 1 end
            local ids = {
                math.floor(aux / 1048576) % 1024,
                math.floor(aux / 1024) % 1024,
                aux % 1024,
            }
            local text = nil
            for k = 1, math.min(count, 3) do
                local key = self:constKey(ids[k]) or "?"
                local id = isIdent(key) and not isKeyword(key)
                if text == nil then
                    text = id and key or ("_G[" .. fmtStr(key) .. "]")
                elseif id then
                    text = text .. "." .. key
                else
                    text = text .. "[" .. fmtStr(key) .. "]"
                end
            end
            self:assign(A, { t = text or "nil", p = 90 })
        elseif op == 13 then
            self:assign(A, { t = wrap(self.regs[B], 90) .. "[" .. wrap(self.regs[C], 1) .. "]", p = 90 })
        elseif op == 15 then
            local key = self:constKey(ins.aux or 0) or "?"
            if isIdent(key) and not isKeyword(key) then
                self:assign(A, { t = wrap(self.regs[B], 90) .. "." .. key, p = 90 })
            else
                self:assign(A, { t = wrap(self.regs[B], 90) .. "[" .. fmtStr(key) .. "]", p = 90 })
            end
        elseif op == 17 then
            self:assign(A, { t = wrap(self.regs[B], 90) .. "[" .. fmtNum(C + 1) .. "]", p = 90 })
        elseif op == 19 or op == 64 then
            local child = nil
            if op == 19 then
                child = self.api.child(self.p.addr, ins.D)
            else
                local v = self.api.kv(self.p.addr, ins.D)
                if type(v) == "function" and self.api.protoaddr then
                    child = self.api.protoaddr(v)
                end
            end
            local text
            if op == 19 and child and child > 0 and self.api.pfield then
                -- CAPTURE instructions follow NEWCLOSURE; map each child
                -- upvalue to the parent register it closes over
                local f = { self.api.pfield(child) }
                local ups, at = {}, nextpc(ins)
                for _ = 1, (f[9] or 0) do
                    local cap = self.p.bypc[at]
                    if not cap or cap.op ~= 70 then break end
                    ups[cap.A] = (self.regs[cap.B] or atom("v" .. cap.B)).t
                    at = nextpc(cap)
                end
                text = self:subFunction(child, ups)
            end
            text = text or (child and child > 0 and self:subFunction(child) or "function() end")
            self:assign(A, { t = text, p = 90, impure = true }, true)
        elseif op == 20 then
            local key = self:constKey(ins.aux or 0) or "?"
            local obj = self.regs[B] or atom("v" .. B)
            if isIdent(key) and not isKeyword(key) then
                self.regs[A] = { t = prefixOf(obj) .. ":" .. key, p = 90 }
            else
                self.regs[A] = { t = prefixOf(obj) .. "[" .. fmtStr(key) .. "]", p = 90 }
            end
            self.regs[A + 1] = obj
            self.method[A] = { obj = obj, name = key }
        elseif op == 33 or op == 34 or op == 35 or op == 36 or op == 37 or op == 38 then
            self:assign(A, bin(ARITH[op], self.regs[B], self.regs[C]))
        elseif op >= 39 and op <= 44 then
            self:assign(A, bin(ARITH[op], self.regs[B], self:const(C)))
        elseif op == 45 then
            self:assign(A, bin("and", self.regs[B], self.regs[C]))
        elseif op == 46 then
            self:assign(A, bin("or", self.regs[B], self.regs[C]))
        elseif op == 47 then
            self:assign(A, bin("and", self.regs[B], self:const(C)))
        elseif op == 48 then
            self:assign(A, bin("or", self.regs[B], self:const(C)))
        elseif op == 49 then
            local e = self.regs[B] or atom("v" .. B)
            for k = B + 1, C do
                e = bin("..", e, self.regs[k] or atom("v" .. k))
            end
            self:assign(A, e)
        elseif op == 50 then
            self:assign(A, un("not", self.regs[B]))
        elseif op == 51 then
            self:assign(A, un("-u", self.regs[B]))
        elseif op == 52 then
            self:assign(A, un("#", self.regs[B]))
        elseif op == 53 then
            self:assign(A, { t = "{}", p = 90, impure = true }, true)
        elseif op == 54 then
            local v = self.api.kv(self.p.addr, ins.D)
            self:assign(A, { t = self:tableText(v, 0), p = 90, impure = true }, true)
        elseif op == 63 then
            local nxt = self.p.bypc[nextpc(ins)]
            if nxt and nxt.op == 21 and nxt.B == 0 and nxt.A == A - 1 then
                -- GETVARARGS feeding a call: render f(...), not a dead local
                self.lastMulti = { base = A, text = "..." }
            else
                self:assign(A, { t = "...", p = 100 })
            end
        end
    end

    function Decompiler:emitAssign(ins)
        local op, A, B, C = ins.op, ins.A, ins.B, ins.C
        local e = self.regs[A] or atom("v" .. A)
        if op == 8 then
            local name = self:constKey(ins.aux or 0) or "?"
            if isIdent(name) and not isKeyword(name) then
                self:stmt(name .. " = " .. e.t)
            else
                self:stmt("_G[" .. fmtStr(name) .. "] = " .. e.t)
            end
        elseif op == 10 then
            self:stmt(self:upName(B) .. " = " .. e.t)
        elseif op == 14 then
            self:stmt(prefixOf(self.regs[B]) .. "[" .. wrap(self.regs[C], 1) .. "] = " .. e.t)
        elseif op == 16 then
            local key = self:constKey(ins.aux or 0) or "?"
            if isIdent(key) and not isKeyword(key) then
                self:stmt(prefixOf(self.regs[B]) .. "." .. key .. " = " .. e.t)
            else
                self:stmt(prefixOf(self.regs[B]) .. "[" .. fmtStr(key) .. "] = " .. e.t)
            end
        elseif op == 18 then
            self:stmt(prefixOf(self.regs[B]) .. "[" .. fmtNum(C + 1) .. "] = " .. e.t)
        elseif op == 55 then
            local tbl = self.regs[A] or atom("v" .. A)
            local n = 0
            if C == 0 then
                local m = self.lastMulti
                self.lastMulti = nil
                self:stmt(wrap(tbl, 90) .. " = { " .. (m and m.text or (self.p.isvararg ~= 0 and "..." or "nil")) .. " }")
            else
                n = C - 1
                local base = ins.aux or 1
                for k = 0, n - 1 do
                    local v = self.regs[B + k] or atom("v" .. (B + k))
                    self:stmt(wrap(tbl, 90) .. "[" .. fmtNum(base + k) .. "] = " .. v.t)
                end
            end
        end
    end

    function Decompiler:buildCall(ins)
        local A, B = ins.A, ins.B
        local method = self.method[A]
        self.method[A] = nil
        local callee, start
        if method then
            callee = prefixOf(method.obj) .. ":" .. method.name
            start = 2
        else
            callee = wrap(self.regs[A] or atom("v" .. A), 90)
            start = 1
        end
        local args = {}
        if B == 0 then
            -- B == 0 means "everything from A+1 to top": fixed arguments
            -- followed by the multi-valued result of the previous call
            local m = self.lastMulti
            if m and m.base >= A + start then
                for k = start, m.base - A - 1 do
                    args[#args + 1] = (self.regs[A + k] or atom("v" .. (A + k))).t
                end
                args[#args + 1] = m.text
                self.lastMulti = nil
            else
                -- unknown multret tail: keep it compilable, "..." is only legal
                -- in a vararg function
                args[1] = self.p.isvararg ~= 0 and "..." or "nil"
            end
        else
            for k = start, B - 1 do
                args[#args + 1] = (self.regs[A + k] or atom("v" .. (A + k))).t
            end
        end
        return callee .. "(" .. table.concat(args, ", ") .. ")"
    end

    -- C == 0 leaves a variable number of results on the stack. When the very
    -- next instruction consumes them, keep the call text for inlining instead
    -- of emitting a temporary and calling twice.
    function Decompiler:consumesMulti(ins)
        local nxt = self.p.bypc[nextpc(ins)]
        if not nxt then return false end
        return (nxt.op == 21 and nxt.B == 0)
            or (nxt.op == 22 and nxt.B == 0)
            or (nxt.op == 55 and nxt.C == 0)
    end

    function Decompiler:emitCall(ins)
        local A, C = ins.A, ins.C
        local callText = self:buildCall(ins)
        if C == 0 then
            self.lastMulti = { base = A, text = callText }
            if not self:consumesMulti(ins) then
                local name = "v" .. A
                if self.declared[A] then self:stmt(name .. " = " .. callText)
                else self:stmt("local " .. name .. " = " .. callText); self.declared[A] = true end
                self.regs[A] = atom(name)
                self.lastMulti = nil
            end
        elseif C == 1 then
            self.lastMulti = nil
            self:stmt(callText)
        else
            self.lastMulti = nil
            local names = {}
            for k = 0, C - 2 do
                names[#names + 1] = "v" .. (A + k)
                self.declared[A + k] = true
                self.regs[A + k] = atom("v" .. (A + k))
            end
            self:stmt("local " .. table.concat(names, ", ") .. " = " .. callText)
        end
    end

    function Decompiler:emitReturn(ins)
        local A, B = ins.A, ins.B
        if B == 1 then
            self:stmt("return")
            return
        end
        local vals = {}
        if B == 0 then
            local m = self.lastMulti
            if m and m.base >= A then
                vals[1] = m.text
                self.lastMulti = nil
            else
                vals[1] = self.p.isvararg ~= 0 and "..." or "nil"
            end
        else
            for k = A, A + B - 2 do
                vals[#vals + 1] = (self.regs[k] or atom("v" .. k)).t
            end
        end
        self:stmt("return " .. table.concat(vals, ", "))
    end

    function Decompiler:predicate(ins)
        local op = ins.op
        if op == 25 then return self.regs[ins.A] or atom("v" .. ins.A) end
        if op == 26 then return self:fnot(self.regs[ins.A] or atom("v" .. ins.A)) end
        if CMP[op] then
            local a = self.regs[ins.A] or atom("v" .. ins.A)
            local b
            if op == 71 or op == 72 then
                b = self:const(ins.aux or 0)
            else
                b = self.regs[(ins.aux or 0) % 256] or atom("v" .. ((ins.aux or 0) % 256))
            end
            -- normalize constant-on-left (a < b -> b > a)
            local opText = CMP[op]
            local an, bn = tonumber(a.t), tonumber(b.t)
            if an ~= nil and bn == nil then
                local inv = { ["<"] = ">", [">"] = "<", ["<="] = ">=", [">="] = "<=", ["=="] = "==", ["~="] = "~=" }
                a, b = b, a
                opText = inv[opText] or opText
            end
            local left, right = wrap(a, 40), wrap(b, 40, true)
            return { t = left .. " " .. opText .. " " .. right, p = 40,
                cmp = opText, left = left, right = right }
        end
        return atom("true")
    end

    function Decompiler:negate(e)
        if e.cmp then
            local inv = { ["=="] = "~=", ["~="] = "==", ["<"] = ">=", ["<="] = ">",
                [">"] = "<=", [">="] = "<" }
            local op = inv[e.cmp] or e.cmp
            return { t = e.left .. " " .. op .. " " .. e.right, p = 40,
                cmp = op, left = e.left, right = e.right }
        end
        return self:fnot(e)
    end

    function Decompiler:snapshot()
        local s = {}
        for k, v in pairs(self.regs) do s[k] = { t = v.t, p = v.p } end
        return s
    end

    function Decompiler:restore(s)
        self.regs = {}
        for k, v in pairs(s) do self.regs[k] = v end
    end

    function Decompiler:mergeIf(before, snapA, snapB, written)
        self.regs = {}
        for k, v in pairs(before) do self.regs[k] = v end
        for _, r in ipairs(written) do
            self.declared[r] = true
            self.regs[r] = atom("v" .. r)
        end
    end

    local FTRUE = { t = "true", p = 100, kind = "const" }
    local FFALSE = { t = "false", p = 100, kind = "const" }

    function Decompiler:fand(a, b)
        if a.kind == "const" then return a.t == "true" and b or a end
        if b.kind == "const" then return b.t == "true" and a or b end
        if a.t == b.t then return a end
        if a.t == "true" then return b end
        if b.t == "true" then return a end
        return { t = wrap(a, 30) .. " and " .. wrap(b, 30, true), p = 30,
            kind = "and", a = a, b = b }
    end

    function Decompiler:forr(a, b)
        if a.kind == "const" then return a.t == "false" and b or a end
        if b.kind == "const" then return b.t == "false" and a or b end
        if a.t == b.t then return a end
        -- x or (not x and y) -> x or y
        if b.kind == "and" and b.a.kind == "not" and b.a.a.t == a.t then
            return self:forr(a, b.b)
        end
        if b.kind == "and" and b.b.kind == "not" and b.b.a.t == a.t then
            return self:forr(a, b.a)
        end
        if a.kind == "and" and a.a.kind == "not" and a.a.a.t == b.t then
            return self:forr(b, a.b)
        end
        if a.kind == "and" and a.b.kind == "not" and a.b.a.t == b.t then
            return self:forr(b, a.a)
        end
        return { t = wrap(a, 20) .. " or " .. wrap(b, 20, true), p = 20,
            kind = "or", a = a, b = b }
    end

    function Decompiler:fnot(a)
        if a.kind == "const" then return a.t == "true" and FFALSE or FTRUE end
        if a.kind == "not" then return a.a end
        if a.cmp then return self:negate(a) end
        return { t = "not " .. wrap(a, 80, true), p = 80, kind = "not", a = a }
    end

    function Decompiler:condRegion(first, hi)
        local conds = {}
        local work = { first.pc }
        local maxpc = first.pc
        local targets = {}
        local function push(pc)
            if not pc or pc < 0 or (hi and pc >= hi) then return end
            local ins = self.p.bypc[pc]
            if ins and isCond(ins) and not conds[pc] then
                work[#work + 1] = pc
            end
        end
        while #work > 0 do
            local pc = table.remove(work)
            local ins = self.p.bypc[pc]
            if ins and isCond(ins) and not conds[pc] and (not hi or pc < hi) then
                conds[pc] = ins
                if pc > maxpc then maxpc = pc end
                local t = targetOf(ins)
                if t then targets[t] = true; push(t) end
                push(nextpc(ins))
            end
        end
        local exit = nil
        for t in pairs(targets) do
            if t > maxpc and (not exit or t > exit) then exit = t end
        end
        exit = exit or targetOf(first) or nextpc(first)
        if hi and exit > hi then exit = hi end
        return conds, maxpc, exit
    end

    -- symbolic reachability. Memoised by pc: without it a region with n
    -- conditions walks 2^n paths and a long script never finishes.
    function Decompiler:reachCond(pc, B, E, memo)
        if pc == B then return FTRUE end
        if pc == E then return FFALSE end
        local ins = self.p.bypc[pc]
        if not ins or not isCond(ins) then
            return (pc >= B and pc < E) and FTRUE or FFALSE
        end
        local hit = memo[pc]
        if hit then return hit end
        local n = (memo.n or 0) + 1
        if n > 4000 then return FFALSE end
        memo.n = n
        memo[pc] = FFALSE -- cycle guard, mirrors the old seen[] behaviour
        local pred = self:predicate(ins)
        local t = targetOf(ins) or E
        local fall = nextpc(ins)
        local a = self:reachCond(t, B, E, memo)
        local b = self:reachCond(fall, B, E, memo)
        local r = self:forr(self:fand(pred, a), self:fand(self:fnot(pred), b))
        memo[pc] = r
        return r
    end

    function Decompiler:emitIf(ins, hi, ctx)
        local conds, _, exit = self:condRegion(ins, hi)
        if exit <= ins.pc then return nextpc(ins) end
        -- every non-condition target inside the region is a possible branch body
        local entrySet = {}
        for pc, c in pairs(conds) do
            local t = targetOf(c)
            if t and t > ins.pc and t < exit and not conds[t] then entrySet[t] = true end
        end
        local last = ins.pc
        for pc in pairs(conds) do if pc > last then last = pc end end
        local fall = nextpc(self.p.bypc[last] or ins)
        if fall < exit then entrySet[fall] = true end
        local entries = {}
        for t in pairs(entrySet) do entries[#entries + 1] = t end
        table.sort(entries)
        if #entries == 0 then return exit end
        local before = self:snapshot()
        local written = {}
        local opened = false
        for i, start in ipairs(entries) do
            local stop = entries[i + 1] or exit
            local cond = self:reachCond(ins.pc, start, stop, {})
            local dead = cond.kind == "const" and cond.t == "false"
            if not dead and start < stop then
                self:restore(before)
                self:stmt((opened and "elseif " or "if ") .. wrap(cond, 1) .. " then")
                self.level = self.level + 1
                self:parseBlock(start, stop,
                    { loopExit = ctx.loopExit, loopHeader = ctx.loopHeader, selfLoop = ctx.selfLoop })
                self.level = self.level - 1
                for r, v in pairs(self.regs) do
                    local found = false
                    for _, x in ipairs(written) do if x == r then found = true; break end end
                    if not found and before[r] and before[r].t ~= v.t then written[#written + 1] = r end
                end
                opened = true
            end
        end
        if opened then self:stmt("end") end
        self:restore(before)
        for _, r in ipairs(written) do
            self.declared[r] = true
            self.regs[r] = atom("v" .. r)
        end
        return exit
    end

    function Decompiler:emitLoop(loop, ctx, hi)
        local p = self.p
        if loop.kind == "fornum" then
            local a = loop.a
            local init = self.regs[a + 2] or atom("v" .. (a + 2))
            local limit = self.regs[a] or atom("v" .. a)
            local step = self.regs[a + 1] or atom("v" .. (a + 1))
            local hasStep = true
            if step.t == "1" then hasStep = false end
            self:stmt("for v" .. (a + 2) .. " = " .. init.t .. ", " .. limit.t
                .. (hasStep and (", " .. step.t) or "") .. " do")
            self.declared[a + 2] = true
            self.regs[a + 2] = atom("v" .. (a + 2))
            self.level = self.level + 1
            self.method = {}
            self:parseBlock(loop.prep.pc + loop.prep.size, loop.loop.pc,
                { loopExit = loop.exit, loopHeader = loop.prep.pc })
            self.level = self.level - 1
            self:stmt("end")
            for r = a, a + 3 do
                if r >= 0 then self.declared[r] = true; self.regs[r] = atom("v" .. r) end
            end
            return loop.exit
        elseif loop.kind == "forgen" then
            local a = loop.a
            local n = loop.count or 2
            local iterText
            if self.pendingIter and ((loop.jump and self.pendingIter.pc == loop.jump.pc - 1)
                or (loop.prep and self.pendingIter.pc == loop.prep.pc - 1)) then
                iterText = self.pendingIter.text
            else
                local parts = {}
                for k = 0, 2 do parts[#parts + 1] = (self.regs[a + k] or atom("v" .. (a + k))).t end
                iterText = table.concat(parts, ", ")
            end
            self.pendingIter = nil
            local names = {}
            for k = 3, 2 + n do
                names[#names + 1] = "v" .. (a + k)
                self.declared[a + k] = true
                self.regs[a + k] = atom("v" .. (a + k))
            end
            self:stmt("for " .. table.concat(names, ", ") .. " in " .. iterText .. " do")
            self.level = self.level + 1
            self.method = {}
            local header = loop.jump and loop.jump.pc or loop.prep.pc
            self:parseBlock(header + (loop.jump and loop.jump.size or loop.prep.size), loop.loop.pc,
                { loopExit = loop.exit, loopHeader = header })
            self.level = self.level - 1
            self:stmt("end")
            for r = a, a + 2 + n do
                if r >= 0 then self.declared[r] = true; self.regs[r] = atom("v" .. r) end
            end
            return loop.exit
        elseif loop.kind == "while" then
            -- the condition may need setup instructions between the jump
            -- target and the compare (LOADK/MOVE/GETTABLE); fold them into the
            -- predicate instead of hoisting statements out of the loop
            local setupLo = loop.cs
            if loop.cond.pc > setupLo then
                self.defer = true
                self:parseBlock(setupLo, loop.cond.pc, { selfLoop = loop })
                self.defer = false
            end
            local cond = self:negate(self:predicate(loop.cond))
            self:stmt("while " .. wrap(cond, 1) .. " do")
            local before = self:snapshot()
            self.level = self.level + 1
            self.method = {}
            self:parseBlock(loop.bodyStart, loop.bodyEnd,
                { loopExit = loop.exit, loopHeader = loop.cs })
            self.level = self.level - 1
            self:stmt("end")
            for r, v in pairs(self.regs) do
                if not before[r] or before[r].t ~= v.t then
                    self.declared[r] = true
                    self.regs[r] = atom("v" .. r)
                end
            end
            return loop.exit
        elseif loop.kind == "repeat" or loop.kind == "repeat2" then
            local cond = loop.cond
            self:stmt("repeat")
            local before = self:snapshot()
            self.level = self.level + 1
            self.method = {}
            local bodyEnd = loop.bodyEnd
            self:parseBlock(loop.bodyStart, bodyEnd,
                { loopExit = loop.exit, loopHeader = loop.cs, selfLoop = loop })
            local pred
            if loop.kind == "repeat" then
                pred = self:predicate(cond)
            else
                pred = self:negate(self:predicate(cond))
            end
            self.level = self.level - 1
            self:stmt("until " .. wrap(pred, 1))
            for r, v in pairs(self.regs) do
                if not before[r] or before[r].t ~= v.t then
                    self.declared[r] = true
                    self.regs[r] = atom("v" .. r)
                end
            end
            return loop.exit
        end
        return nextpc(loop.prep or loop.jump or loop.cond)
    end

    function Decompiler:afterJump(ins)
        return ins.pc + ins.size
    end

    function Decompiler:parseBlock(lo, hi, ctx)
        ctx = ctx or {}
        local pc = lo
        local guard = 0
        while pc < hi and self.lines < self.maxLines do
            guard = guard + 1
            if guard > 20000 then break end
            -- long scripts freeze the client otherwise; a yield every 1500
            -- instructions keeps the frame alive and is ignored if the caller
            -- cannot yield
            if guard % 1500 == 0 and type(task) == "table" and task.wait then
                pcall(task.wait)
            end
            self.stage = "pc=" .. tostring(pc) .. " hi=" .. tostring(hi)
            local ins = self.p.bypc[pc]
            if not ins then
                pc = pc + 1
            else
                local loop = self.loops[pc]
                local loopStart = loop and (loop.cs or (loop.prep and loop.prep.pc) or (loop.jump and loop.jump.pc))
                if loop and pc == loopStart and loop ~= ctx.selfLoop then
                    pc = self:emitLoop(loop, ctx, hi)
                elseif isCond(ins) then
                    local t = targetOf(ins)
                    if t and t <= pc then
                        -- stray back edge (handled by loop prescan)
                        pc = nextpc(ins)
                    else
                        pc = self:emitIf(ins, hi, ctx)
                    end
                elseif isJump(ins) then
                    local t = targetOf(ins)
                    if t and t < pc then
                        if ctx.loopHeader and t <= ctx.loopHeader then self:stmt("continue") end
                        pc = nextpc(ins)
                    elseif t and t >= hi then
                        if ctx.loopExit and t >= ctx.loopExit then self:stmt("break") end
                        pc = hi
                    else
                        pc = nextpc(ins)
                    end
                elseif ins.op == 22 then
                    self:emitReturn(ins)
                    pc = hi
                elseif ins.op == 8 or ins.op == 10 or ins.op == 14 or ins.op == 16
                    or ins.op == 18 or ins.op == 55 then
                    self:emitAssign(ins)
                    pc = nextpc(ins)
                elseif ins.op == 21 then
                    -- generic for: the CALL directly feeds the iterator triple
                    local nxt = self.p.bypc[nextpc(ins)]
                    local jl = nil
                    if nxt and (isJump(nxt) or nxt.op == 61 or nxt.op == 59) then
                        jl = self.loops[nxt.pc]
                    end
                    if jl and jl.kind == "forgen" then
                        local callee = wrap(self.regs[ins.A] or atom("v" .. ins.A), 90)
                        local args = {}
                        for k = 1, ins.B - 1 do
                            args[#args + 1] = (self.regs[ins.A + k] or atom("v" .. (ins.A + k))).t
                        end
                        self.pendingIter = {
                            pc = ins.pc,
                            text = callee .. "(" .. table.concat(args, ", ") .. ")",
                        }
                        self.regs[ins.A] = atom("v" .. ins.A)
                        self.regs[ins.A + 1] = atom("v" .. (ins.A + 1))
                        self.regs[ins.A + 2] = atom("v" .. (ins.A + 2))
                        pc = nextpc(ins)
                    else
                        local ret = self.p.bypc[nextpc(ins)]
                        if ret and ret.op == 22 and ret.A == ins.A and ret.B == 0 then
                            -- multi-return tail call: return f(...)
                            self:stmt("return " .. self:buildCall(ins))
                            pc = nextpc(ret)
                        else
                            self:emitCall(ins)
                            pc = nextpc(ins)
                        end
                    end
                elseif ins.op == 19 or ins.op == 64 or ins.op == 4 or ins.op == 5
                    or ins.op == 3 or ins.op == 2 or ins.op == 6 or ins.op == 7
                    or ins.op == 9 or ins.op == 12 or ins.op == 13 or ins.op == 15
                    or ins.op == 17 or ins.op == 20 or ins.op == 33 or ins.op == 34
                    or ins.op == 35 or ins.op == 36 or ins.op == 37 or ins.op == 38
                    or (ins.op >= 39 and ins.op <= 44) or ins.op == 45 or ins.op == 46
                    or ins.op == 47 or ins.op == 48 or ins.op == 49 or ins.op == 50
                    or ins.op == 51 or ins.op == 52 or ins.op == 53 or ins.op == 54
                    or ins.op == 63 or ins.op == 66 then
                    self:emitValue(ins)
                    pc = nextpc(ins)
                else
                    pc = nextpc(ins)
                end
            end
        end
        return pc
    end

    function Decompiler:run(topLevel)
        local p = self.p
        local params = {}
        for r = 0, p.numparams - 1 do params[#params + 1] = "v" .. r end
        if p.isvararg ~= 0 then params[#params + 1] = "..." end
        local name = p.debugname
        local head
        if isIdent(name or "") and not isKeyword(name) then
            head = "function " .. name .. "(" .. table.concat(params, ", ") .. ")"
        else
            head = "function(" .. table.concat(params, ", ") .. ")"
        end
        self:parseBlock(0, p.sizecode, {})
        -- drop a trailing bare return; every chunk has one
        local n = #self.out
        while n > 0 and self.out[n]:match("^%s*$") do n = n - 1 end
        if n > 0 and self.out[n]:match("^%s*return%s*$") then
            table.remove(self.out, n)
        end
        local body = table.concat(self.out, "\n")
        if topLevel and not isIdent(name or "") then return body end
        if body == "" then return head .. "\nend" end
        return head .. "\n" .. body .. "\nend"
    end

    -- ---------- public ----------
    -- Dex re-opens the same script constantly; content-keyed so a recycled
    -- proto address can never serve the wrong text
    local protoCache, protoCacheN = {}, 0
    local function decompileProto(addr, topLevel)
        if not validProto(addr) then return nil end
        local f = { api.pfield(addr) }
        local key = tostring(f[1]) .. "|" .. tostring(f[3]) .. "|" .. tostring(f[4]) .. "|" .. tostring(topLevel)
        local hit = protoCache[key]
        if hit then return hit end
        local d = newDecompiler(addr, 0, {})
        if not d then return nil end
        local ok, text = pcall(d.run, d, topLevel)
        if not ok then
            local why = tostring(text) .. " [" .. tostring(d.stage) .. "]"
            local partial = d.out and table.concat(d.out, "\n") or ""
            if #partial > 0 then
                -- keep everything decompiled before the bad instruction
                return partial .. "\n-- [decompiler stopped: " .. why .. "]"
            end
            return nil, why
        end
        if type(text) == "string" and #text > 0 then
            if protoCacheN > 200 then protoCache, protoCacheN = {}, 0 end
            protoCache[key] = text
            protoCacheN = protoCacheN + 1
        end
        return text
    end

    -- one scan serves every lookup in a burst; rebuilding it per instance is
    -- far too slow to walk game:GetDescendants(). A miss forces a rescan so
    -- scripts loaded after the index was built still resolve.
    -- Each line is "addr\tsource\tcode\tchildcsv" (older scans: "addr\tsource").
    local scanIndex, scanById, scanIndexAt = nil, nil, 0
    local scanLock = false
    local function getScanIndex(force)
        -- a locked batch (saveinstance) gets one snapshot: the scan walks the
        -- whole address space, so rescanning mid-run freezes the client
        if scanLock and scanIndex then return scanIndex end
        local now = os.clock()
        local age = now - scanIndexAt
        -- a miss may rescan, but never more than once every 30 s: walking a lot
        -- of instances makes many lookups miss and each scan is ~1 s
        if scanIndex and age < 30 then return scanIndex end
        scanIndexAt = now
        scanIndex, scanById = {}, {}
        local raw = api.scan and api.scan()
        if not raw or raw == "" then return scanIndex end
        for line in raw:gmatch("[^\n]+") do
            local a, rest = line:match("^(%x+)\t(.*)$")
            if a then
                local n = tonumber(a, 16)
                if n then
                    local src, sc, kids = rest:match("^(.-)\t(%d+)\t([%x,]*)$")
                    if not src then src = rest end
                    local list = scanIndex[src]
                    if not list then list = {}; scanIndex[src] = list end
                    list[#list + 1] = { addr = n, code = tonumber(sc) or 0, kids = kids, src = src }
                end
            end
        end
        -- templates and their running clones share the trailing name; map it
        -- so a script with no exact proto can borrow its clone's bytecode
        for src in pairs(scanIndex) do
            local name = src:match("([^%.]+)$")
            if name then
                local t = scanById[name]
                if not t then t = {}; scanById[name] = t end
                t[#t + 1] = src
            end
        end
        return scanIndex
    end

    local function lookup(source, force)
        local entries = getScanIndex(force)[source]
        if entries then return entries end
        local name = source:match("([^%.]+)$")
        local sources = name and scanById and scanById[name]
        if not sources then return nil end

        local wanted = {}
        for p in source:gmatch("[^%.]+") do wanted[#wanted + 1] = p end

        local bestScore, best = -1, nil
        for _, src in ipairs(sources) do
            local parts = {}
            for p in src:gmatch("[^%.]+") do parts[#parts + 1] = p end
            local score = 0
            while score < #parts and score < #wanted and
                parts[#parts - score] == wanted[#wanted - score] do
                score = score + 1
            end
            local list = scanIndex[src]
            if list and #list > 0 then
                if score > bestScore then
                    bestScore, best = score, {}
                end
                if score == bestScore then
                    for _, e in ipairs(list) do best[#best + 1] = e end
                end
            end
        end
        return best
    end

    local function findSourceProtos(source)
        local list = lookup(source, false) or lookup(source, true)
        local out = {}
        for _, e in ipairs(list or {}) do out[#out + 1] = e.addr end
        return out
    end

    -- the scan carries each proto's child addresses, so picking the chunk
    -- root costs no cross-VM calls at all
    local function pickMain(entries)
        local cands, childSet, indexed = {}, {}, false
        for _, e in ipairs(entries) do
            cands[#cands + 1] = e.addr
            if e.kids then
                indexed = true
                for h in e.kids:gmatch("%x+") do childSet[tonumber(h, 16)] = true end
            end
        end
        local main
        if indexed then
            for _, e in ipairs(entries) do
                if not childSet[e.addr] and (not main or (e.code or 0) > (main.code or 0)) then
                    main = e
                end
            end
        else
            -- scan from an older DLL: fall back to reading child pointers
            for _, e in ipairs(entries) do
                local f = { api.pfield(e.addr) }
                for i = 0, (f[5] or 0) - 1 do
                    local c = api.child(e.addr, i)
                    if c and c > 0 then childSet[c] = true end
                end
            end
            for _, e in ipairs(entries) do
                if not childSet[e.addr] then
                    if not main then main = e
                    else
                        local fa = { api.pfield(e.addr) }
                        local fm = { api.pfield(main.addr) }
                        if (fa[3] or 0) > (fm[3] or 0) then main = e end
                    end
                end
            end
        end
        return main or entries[1], cands
    end

    local function findMain(source)
        local entries = lookup(source, false)
        if not entries then entries = lookup(source, true) end
        if not entries or #entries == 0 then return nil, {} end
        local main, cands = pickMain(entries)
        -- a proto can be collected between the scan and the decompile;
        -- only trust the entry while its source still matches
        local f = { api.pfield(main.addr) }
        if f[1] == (main.src or source) then return main.addr, cands end
        getScanIndex(true)
        entries = lookup(source, true)
        if not entries or #entries == 0 then return nil, {} end
        main, cands = pickMain(entries)
        f = { api.pfield(main.addr) }
        if f[1] == (main.src or source) then return main.addr, cands end
        return nil, {}
    end

    local function disasm(addr)
        local p = loadProto(addr)
        if not p then return "nil proto" end
        local out = {}
        for _, ins in ipairs(p.order) do
            local s = string.format("%4d %-14s A=%d B=%d C=%d D=%d",
                ins.pc, ins.name, ins.A, ins.B, ins.C, ins.D)
            if ins.aux then s = s .. string.format(" aux=%08x", ins.aux) end
            out[#out + 1] = s
        end
        return table.concat(out, "\n")
    end

    return {
        proto = decompileProto,
        findMain = findMain,
        findSourceProtos = findSourceProtos,
        -- drop the cached scan so a script compiled after the last index is
        -- visible immediately (used when a module is force-loaded for Dex)
        invalidate = function() scanIndex, scanIndexAt = nil, 0 end,
        -- hold one snapshot for a whole batch; rescanning mid-walk freezes
        lock = function() scanLock = true end,
        unlock = function() scanLock = false end,
        load = loadProto,
        disasm = disasm,
    }
end

return build
