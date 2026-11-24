--[[
    HTTPspy | Synapse X
    Logs every outbound HTTP call made through the executor bridge:
      request / syn.request / http_request / http.request / game:HttpGet(Async)
    Engine-internal requests cannot be seen from Lua; this covers everything
    scripts (and the executor) send through this client.
]]
local env = (getgenv and getgenv()) or _G

local previous = env.__octane_httpspy
if previous and previous.uninstall then
    pcall(previous.uninstall)
end

----------------------------------------------------------------------
-- palette / helpers
----------------------------------------------------------------------
local BG      = Color3.fromRGB(18, 18, 18)
local PANEL   = Color3.fromRGB(31, 31, 31)
local PANEL2  = Color3.fromRGB(38, 38, 38)
local LINE    = Color3.fromRGB(58, 58, 58)
local TEXT    = Color3.fromRGB(232, 232, 232)
local MUTED   = Color3.fromRGB(148, 148, 148)
local ACCENT  = Color3.fromRGB(1, 135, 134)
local ACCENT2 = Color3.fromRGB(55, 0, 179)
local GREEN   = Color3.fromRGB(62, 166, 96)
local RED     = Color3.fromRGB(207, 102, 121)
local YELLOW  = Color3.fromRGB(240, 190, 80)

local function mk(class, props, parent)
    local inst = Instance.new(class)
    for k, v in next, props do
        inst[k] = v
    end
    if parent then
        inst.Parent = parent
    end
    return inst
end

local function corner(inst, radius)
    local c = Instance.new("UICorner")
    c.CornerRadius = UDim.new(0, radius or 6)
    c.Parent = inst
    return c
end

local function stroke(inst, color)
    pcall(function()
        local s = Instance.new("UIStroke")
        s.Color = color or LINE
        s.Thickness = 1
        s.Parent = inst
    end)
end

local function toast(text)
    if not statusLabel then return end
    local old = statusLabel.Text
    statusLabel.Text = text
    statusLabel.TextColor3 = GREEN
    task.delay(1.2, function()
        if statusLabel and statusLabel.Text == text then
            statusLabel.Text = old
            statusLabel.TextColor3 = MUTED
        end
    end)
end

local function copy(text)
    if setclipboard then
        pcall(setclipboard, text)
        toast("Copied to clipboard")
    elseif env.syn and env.syn.write_clipboard then
        pcall(env.syn.write_clipboard, text)
        toast("Copied to clipboard")
    elseif toclipboard then
        pcall(toclipboard, text)
        toast("Copied to clipboard")
    else
        toast("No clipboard API")
    end
end

local function quote(s)
    return "'" .. tostring(s):gsub("'", "'\\''") .. "'"
end

local function fmtHeaders(h)
    if type(h) ~= "table" then
        return tostring(h or "")
    end
    local out = {}
    for k, v in pairs(h) do
        out[#out + 1] = tostring(k) .. ": " .. tostring(v)
    end
    table.sort(out)
    return table.concat(out, "\n")
end

local function clip(s, n)
    s = tostring(s or "")
    if #s > n then
        return s:sub(1, n) .. "\n… truncated (" .. #s .. " bytes total)"
    end
    return s
end

local function statusText(e)
    if e.error then return "ERROR" end
    if e.status then return tostring(e.status) end
    return "—"
end

local function statusColor(e)
    if e.error then return RED end
    local code = tonumber(e.status)
    if not code then return MUTED end
    if code >= 200 and code < 300 then return GREEN end
    if code >= 300 and code < 400 then return YELLOW end
    return RED
end

local function methodColor(m)
    if m == "GET" then return ACCENT end
    if m == "POST" then return YELLOW end
    return ACCENT2
end

local function shortUrl(url)
    url = tostring(url or "?")
    url = url:gsub("^https?://", "")
    if #url > 72 then
        url = url:sub(1, 69) .. "..."
    end
    return url
end

----------------------------------------------------------------------
-- window
----------------------------------------------------------------------
local parent = (gethui and gethui()) or game:GetService("CoreGui")
pcall(function()
    local old = parent:FindFirstChild("HTTPspy")
    if old then old:Destroy() end
end)

local gui = mk("ScreenGui", {
    Name = "HTTPspy",
    ResetOnSpawn = false,
    IgnoreGuiInset = true,
    DisplayOrder = 999,
    ZIndexBehavior = Enum.ZIndexBehavior.Sibling,
}, parent)

local main = mk("Frame", {
    Name = "Main",
    BackgroundColor3 = BG,
    BorderSizePixel = 0,
    Position = UDim2.new(0.5, 0, 0.5, 0),
    AnchorPoint = Vector2.new(0.5, 0.5),
    Size = UDim2.new(0, 740, 0, 440),
    ClipsDescendants = true,
    Active = true,
}, gui)
corner(main, 8)
stroke(main, LINE)

local titleBar = mk("Frame", {
    BackgroundColor3 = PANEL,
    BorderSizePixel = 0,
    Size = UDim2.new(1, 0, 0, 34),
}, main)

local logo = mk("TextLabel", {
    BackgroundTransparency = 1,
    Position = UDim2.new(0, 12, 0, 0),
    Size = UDim2.new(0, 22, 1, 0),
    Font = Enum.Font.GothamBlack,
    Text = "X",
    TextColor3 = GREEN,
    TextSize = 18,
    TextXAlignment = Enum.TextXAlignment.Left,
}, titleBar)

mk("TextLabel", {
    BackgroundTransparency = 1,
    Position = UDim2.new(0, 36, 0, 0),
    Size = UDim2.new(0, 120, 1, 0),
    Font = Enum.Font.GothamBold,
    Text = "Synapse X",
    TextColor3 = TEXT,
    TextSize = 14,
    TextXAlignment = Enum.TextXAlignment.Left,
}, titleBar)

mk("TextLabel", {
    BackgroundTransparency = 1,
    Position = UDim2.new(0, 132, 0, 0),
    Size = UDim2.new(0, 120, 1, 0),
    Font = Enum.Font.Gotham,
    Text = "— HTTPspy",
    TextColor3 = MUTED,
    TextSize = 13,
    TextXAlignment = Enum.TextXAlignment.Left,
}, titleBar)

local gradientLine = mk("Frame", {
    BackgroundColor3 = ACCENT,
    BorderSizePixel = 0,
    Position = UDim2.new(0, 0, 0, 33),
    Size = UDim2.new(1, 0, 0, 1),
}, main)
do
    local g = Instance.new("UIGradient")
    g.Color = ColorSequence.new({
        ColorSequenceKeypoint.new(0, ACCENT),
        ColorSequenceKeypoint.new(0.5, ACCENT2),
        ColorSequenceKeypoint.new(1, ACCENT),
    })
    g.Parent = gradientLine
end

local minimizeButton = mk("TextButton", {
    BackgroundTransparency = 1,
    Position = UDim2.new(1, -62, 0, 0),
    Size = UDim2.new(0, 30, 1, 0),
    Font = Enum.Font.GothamBold,
    Text = "—",
    TextColor3 = MUTED,
    TextSize = 14,
}, titleBar)

local closeButton = mk("TextButton", {
    BackgroundTransparency = 1,
    Position = UDim2.new(1, -32, 0, 0),
    Size = UDim2.new(0, 30, 1, 0),
    Font = Enum.Font.GothamBold,
    Text = "X",
    TextColor3 = MUTED,
    TextSize = 13,
}, titleBar)

local toolbar = mk("Frame", {
    BackgroundColor3 = PANEL,
    BorderSizePixel = 0,
    Position = UDim2.new(0, 0, 0, 34),
    Size = UDim2.new(1, 0, 0, 40),
}, main)

local search = mk("TextBox", {
    BackgroundColor3 = PANEL2,
    BorderSizePixel = 0,
    Position = UDim2.new(0, 10, 0, 8),
    Size = UDim2.new(0, 250, 0, 24),
    Font = Enum.Font.Gotham,
    PlaceholderText = "Filter by URL, method or status…",
    PlaceholderColor3 = MUTED,
    Text = "",
    TextColor3 = TEXT,
    TextSize = 13,
    TextXAlignment = Enum.TextXAlignment.Left,
    ClearTextOnFocus = false,
    ClipsDescendants = true,
}, toolbar)
corner(search, 4)
do
    local pad = Instance.new("UIPadding")
    pad.PaddingLeft = UDim.new(0, 8)
    pad.Parent = search
end

local filter = "All"
local filterButtons = {}
local function makeFilter(name, x)
    local b = mk("TextButton", {
        BackgroundColor3 = PANEL2,
        BorderSizePixel = 0,
        Position = UDim2.new(0, x, 0, 8),
        Size = UDim2.new(0, 56, 0, 24),
        Font = Enum.Font.Gotham,
        Text = name,
        TextColor3 = MUTED,
        TextSize = 12,
    }, toolbar)
    corner(b, 4)
    b.MouseButton1Click:Connect(function()
        filter = name
        for n, btn in pairs(filterButtons) do
            btn.TextColor3 = n == name and TEXT or MUTED
            btn.BackgroundColor3 = n == name and ACCENT or PANEL2
        end
        rebuild()
    end)
    filterButtons[name] = b
    return b
end
makeFilter("All", 270)
makeFilter("POST", 330)
makeFilter("Errors", 390)

local clearButton = mk("TextButton", {
    BackgroundColor3 = PANEL2,
    BorderSizePixel = 0,
    Position = UDim2.new(1, -70, 0, 8),
    Size = UDim2.new(0, 60, 0, 24),
    Font = Enum.Font.Gotham,
    Text = "Clear",
    TextColor3 = MUTED,
    TextSize = 12,
}, toolbar)
corner(clearButton, 4)

----------------------------------------------------------------------
-- list
----------------------------------------------------------------------
local listFrame = mk("Frame", {
    BackgroundColor3 = PANEL,
    BorderSizePixel = 0,
    Position = UDim2.new(0, 10, 0, 82),
    Size = UDim2.new(0, 300, 1, -116),
}, main)
corner(listFrame, 6)

local listScroll = mk("ScrollingFrame", {
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    Position = UDim2.new(0, 4, 0, 6),
    Size = UDim2.new(1, -8, 1, -12),
    CanvasSize = UDim2.new(0, 0, 0, 0),
    ScrollBarThickness = 4,
    ScrollBarImageColor3 = ACCENT,
    ScrollBarImageTransparency = 0.3,
    ClipsDescendants = true,
}, listFrame)

----------------------------------------------------------------------
-- details
----------------------------------------------------------------------
local detailFrame = mk("Frame", {
    BackgroundColor3 = PANEL,
    BorderSizePixel = 0,
    Position = UDim2.new(0, 318, 0, 82),
    Size = UDim2.new(1, -328, 1, -116),
}, main)
corner(detailFrame, 6)

local detailTitle = mk("TextLabel", {
    BackgroundTransparency = 1,
    Position = UDim2.new(0, 10, 0, 6),
    Size = UDim2.new(1, -180, 0, 20),
    Font = Enum.Font.GothamBold,
    Text = "Select a request",
    TextColor3 = TEXT,
    TextSize = 12,
    TextXAlignment = Enum.TextXAlignment.Left,
    TextTruncate = Enum.TextTruncate.AtEnd,
}, detailFrame)

local function copyButton(text, x, width)
    local b = mk("TextButton", {
        BackgroundColor3 = PANEL2,
        BorderSizePixel = 0,
        Position = UDim2.new(1, x, 0, 6),
        Size = UDim2.new(0, width, 0, 20),
        Font = Enum.Font.Gotham,
        Text = text,
        TextColor3 = MUTED,
        TextSize = 11,
    }, detailFrame)
    corner(b, 4)
    return b
end

local copyUrl = copyButton("URL", -132, 38)
local copyCurl = copyButton("cURL", -90, 42)
local copyBody = copyButton("Body", -44, 36)

local detailScroll = mk("ScrollingFrame", {
    BackgroundTransparency = 1,
    BorderSizePixel = 0,
    Position = UDim2.new(0, 8, 0, 30),
    Size = UDim2.new(1, -16, 1, -36),
    CanvasSize = UDim2.new(0, 0, 0, 0),
    ScrollBarThickness = 4,
    ScrollBarImageColor3 = ACCENT,
    ScrollBarImageTransparency = 0.3,
    ClipsDescendants = true,
}, detailFrame)

local detailText = mk("TextLabel", {
    BackgroundTransparency = 1,
    Position = UDim2.new(0, 2, 0, 0),
    Size = UDim2.new(1, -8, 0, 0),
    Font = Enum.Font.Code,
    Text = "",
    TextColor3 = TEXT,
    TextSize = 12,
    TextWrapped = true,
    TextXAlignment = Enum.TextXAlignment.Left,
    TextYAlignment = Enum.TextYAlignment.Top,
}, detailScroll)

----------------------------------------------------------------------
-- footer
----------------------------------------------------------------------
local footer = mk("Frame", {
    BackgroundColor3 = PANEL,
    BorderSizePixel = 0,
    Position = UDim2.new(0, 0, 1, -26),
    Size = UDim2.new(1, 0, 0, 26),
}, main)

statusLabel = mk("TextLabel", {
    BackgroundTransparency = 1,
    Position = UDim2.new(0, 10, 0, 0),
    Size = UDim2.new(0, 420, 1, 0),
    Font = Enum.Font.Gotham,
    Text = "● Spying — 0 captured",
    TextColor3 = MUTED,
    TextSize = 11,
    TextXAlignment = Enum.TextXAlignment.Left,
}, footer)

mk("TextLabel", {
    BackgroundTransparency = 1,
    Position = UDim2.new(1, -330, 0, 0),
    Size = UDim2.new(0, 322, 1, 0),
    Font = Enum.Font.Gotham,
    Text = "request · syn.request · http_request · game:HttpGet",
    TextColor3 = MUTED,
    TextSize = 11,
    TextXAlignment = Enum.TextXAlignment.Right,
}, footer)

----------------------------------------------------------------------
-- state / rendering
----------------------------------------------------------------------
local MAX = 300
local entries = {}
local selected = nil

local function matches(e)
    if filter == "Errors" and not e.error and not (tonumber(e.status) and tonumber(e.status) >= 400) then
        return false
    end
    if filter == "POST" and e.method ~= "POST" then
        return false
    end
    local q = search.Text:lower()
    if #q > 0 then
        local hay = (e.method .. " " .. tostring(e.url) .. " " .. statusText(e)):lower()
        if not hay:find(q, 1, true) then
            return false
        end
    end
    return true
end

local function detailString(e)
    local out = {}
    out[#out + 1] = (e.method or "GET") .. "  " .. tostring(e.url or "?")
    out[#out + 1] = string.rep("─", 74)
    out[#out + 1] = "Time      " .. os.date("%H:%M:%S", e.time) .. "   Duration " .. tostring(e.ms or 0) .. " ms"
    out[#out + 1] = "Status    " .. statusText(e) .. (e.error and ("   " .. tostring(e.error)) or "")
    out[#out + 1] = ""
    out[#out + 1] = "── REQUEST HEADERS " .. string.rep("─", 50)
    out[#out + 1] = fmtHeaders(e.reqHeaders)
    out[#out + 1] = ""
    out[#out + 1] = "── REQUEST BODY " .. string.rep("─", 52)
    out[#out + 1] = clip(e.reqBody, 8000)
    out[#out + 1] = ""
    out[#out + 1] = "── RESPONSE HEADERS " .. string.rep("─", 49)
    out[#out + 1] = fmtHeaders(e.resHeaders)
    out[#out + 1] = ""
    out[#out + 1] = "── RESPONSE BODY " .. string.rep("─", 52)
    out[#out + 1] = clip(e.resBody, 8000)
    return table.concat(out, "\n")
end

local function estimateHeight(s)
    local lines = 0
    for line in (s .. "\n"):gmatch("(.-)\n") do
        lines = lines + math.max(1, math.ceil(#line / 92))
    end
    return lines * 16 + 12
end

local function renderDetails()
    if not selected then
        detailTitle.Text = "Select a request"
        detailText.Text = ""
        detailScroll.CanvasSize = UDim2.new(0, 0, 0, 0)
        return
    end
    detailTitle.Text = (selected.method or "GET") .. "  " .. tostring(selected.url or "?")
    local text = detailString(selected)
    detailText.Text = text
    local h = estimateHeight(text)
    detailText.Size = UDim2.new(1, -8, 0, h)
    detailScroll.CanvasSize = UDim2.new(0, 0, 0, h + 8)
end

function rebuild()
    for _, child in ipairs(listScroll:GetChildren()) do
        if child:IsA("GuiObject") then
            child:Destroy()
        end
    end

    local shown = 0
    local y = 0
    for _, e in ipairs(entries) do
        if matches(e) and shown < 120 then
            shown = shown + 1
            local isSelected = e == selected
            local row = mk("TextButton", {
                BackgroundColor3 = isSelected and PANEL2 or BG,
                BorderSizePixel = 0,
                Position = UDim2.new(0, 0, 0, y),
                Size = UDim2.new(1, -4, 0, 42),
                Text = "",
                AutoButtonColor = false,
                ClipsDescendants = true,
            }, listScroll)
            corner(row, 4)

            local badge = mk("TextLabel", {
                BackgroundColor3 = methodColor(e.method),
                BorderSizePixel = 0,
                Position = UDim2.new(0, 6, 0, 7),
                Size = UDim2.new(0, 42, 0, 16),
                Font = Enum.Font.GothamBold,
                Text = e.method or "GET",
                TextColor3 = Color3.fromRGB(10, 10, 10),
                TextSize = 10,
            }, row)
            corner(badge, 3)

            mk("TextLabel", {
                BackgroundTransparency = 1,
                Position = UDim2.new(0, 52, 0, 4),
                Size = UDim2.new(1, -58, 0, 18),
                Font = Enum.Font.Gotham,
                Text = shortUrl(e.url),
                TextColor3 = TEXT,
                TextSize = 12,
                TextXAlignment = Enum.TextXAlignment.Left,
                TextTruncate = Enum.TextTruncate.AtEnd,
            }, row)

            mk("TextLabel", {
                BackgroundTransparency = 1,
                Position = UDim2.new(0, 52, 0, 22),
                Size = UDim2.new(1, -58, 0, 14),
                Font = Enum.Font.Gotham,
                Text = os.date("%H:%M:%S", e.time) .. "  ·  " .. tostring(e.ms or 0) .. " ms",
                TextColor3 = MUTED,
                TextSize = 10,
                TextXAlignment = Enum.TextXAlignment.Left,
            }, row)

            mk("TextLabel", {
                BackgroundTransparency = 1,
                Position = UDim2.new(1, -48, 0, 22),
                Size = UDim2.new(0, 42, 0, 14),
                Font = Enum.Font.GothamBold,
                Text = statusText(e),
                TextColor3 = statusColor(e),
                TextSize = 10,
                TextXAlignment = Enum.TextXAlignment.Right,
            }, row)

            row.MouseEnter:Connect(function()
                if e ~= selected then row.BackgroundColor3 = PANEL2 end
            end)
            row.MouseLeave:Connect(function()
                if e ~= selected then row.BackgroundColor3 = BG end
            end)
            row.MouseButton1Click:Connect(function()
                selected = e
                rebuild()
                renderDetails()
            end)

            y = y + 46
        end
    end

    listScroll.CanvasSize = UDim2.new(0, 0, 0, y)
    statusLabel.Text = "● Spying — " .. #entries .. " captured" .. (#entries > shown and (" (" .. shown .. " shown)") or "")
    statusLabel.TextColor3 = MUTED
    renderDetails()
end

local dirty = false
local scheduled = false
local function markDirty()
    dirty = true
    if scheduled then return end
    scheduled = true
    task.delay(0.15, function()
        scheduled = false
        if dirty then
            dirty = false
            pcall(rebuild)
        end
    end)
end

----------------------------------------------------------------------
-- hooks
----------------------------------------------------------------------
local original = env.request
if type(original) ~= "function" then
    original = env.syn and env.syn.request
end
if type(original) ~= "function" then
    warn("[HTTPspy] this executor exposes no request API")
    return
end

local function record(opts, res, err, started)
    opts = type(opts) == "table" and opts or {}
    local url = opts.Url or opts.url
    local method = tostring(opts.Method or opts.method or "GET"):upper()

    local entry = {
        time = os.time(),
        method = method,
        url = tostring(url or "<no url>"),
        reqHeaders = opts.Headers or opts.headers,
        reqBody = opts.Body or opts.body,
        ms = math.floor((tick() - started) * 1000 + 0.5),
    }

    if type(res) == "table" then
        entry.status = res.StatusCode or res.Status
        entry.resHeaders = res.Headers
        entry.resBody = res.Body
    elseif err ~= nil then
        entry.error = tostring(err)
    end

    table.insert(entries, 1, entry)
    if #entries > MAX then
        table.remove(entries)
    end
    markDirty()
end

local function spy(opts)
    local started = tick()
    local ok, res, err = pcall(original, opts)
    if not ok then
        record(opts, nil, res, started)
        error(res, 0)
    end
    record(opts, res, err, started)
    return res, err
end

local hooked = (newcclosure and newcclosure(spy)) or spy

env.request = hooked
env.http_request = hooked
if env.syn then env.syn.request = hooked end
if env.http then env.http.request = hooked end

----------------------------------------------------------------------
-- buttons / lifecycle
----------------------------------------------------------------------
search:GetPropertyChangedSignal("Text"):Connect(function()
    markDirty()
end)

clearButton.MouseButton1Click:Connect(function()
    entries = {}
    selected = nil
    rebuild()
end)

copyUrl.MouseButton1Click:Connect(function()
    if selected then copy(tostring(selected.url or "")) end
end)

copyBody.MouseButton1Click:Connect(function()
    if selected then copy(tostring(selected.resBody or selected.error or "")) end
end)

copyCurl.MouseButton1Click:Connect(function()
    if not selected then return end
    local e = selected
    local parts = { "curl -X " .. (e.method or "GET") }
    if type(e.reqHeaders) == "table" then
        for k, v in pairs(e.reqHeaders) do
            parts[#parts + 1] = "-H " .. quote(tostring(k) .. ": " .. tostring(v))
        end
    end
    if e.reqBody and #tostring(e.reqBody) > 0 then
        parts[#parts + 1] = "--data-raw " .. quote(e.reqBody)
    end
    parts[#parts + 1] = quote(e.url)
    copy(table.concat(parts, " \\\n  "))
end)

local function uninstall()
    if env.request == hooked then env.request = original end
    if env.http_request == hooked then env.http_request = original end
    if env.syn and env.syn.request == hooked then env.syn.request = original end
    if env.http and env.http.request == hooked then env.http.request = original end
    if env.__octane_httpspy and env.__octane_httpspy.uninstall == uninstall then
        env.__octane_httpspy = nil
    end
    pcall(function() gui:Destroy() end)
end

env.__octane_httpspy = { uninstall = uninstall }

----------------------------------------------------------------------
-- dragging / minimize
----------------------------------------------------------------------
local dragging, dragStart, startPos = false, nil, nil
titleBar.InputBegan:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        dragging = true
        dragStart = input.Position
        startPos = main.Position
    end
end)
titleBar.InputEnded:Connect(function(input)
    if input.UserInputType == Enum.UserInputType.MouseButton1 or input.UserInputType == Enum.UserInputType.Touch then
        dragging = false
    end
end)
local userInput = game:GetService("UserInputService")
userInput.InputChanged:Connect(function(input)
    if dragging and (input.UserInputType == Enum.UserInputType.MouseMovement or input.UserInputType == Enum.UserInputType.Touch) then
        local delta = input.Position - dragStart
        main.Position = UDim2.new(startPos.X.Scale, startPos.X.Offset + delta.X, startPos.Y.Scale, startPos.Y.Offset + delta.Y)
    end
end)

local pill = mk("TextButton", {
    BackgroundColor3 = PANEL,
    BorderSizePixel = 0,
    Position = UDim2.new(0, 20, 0, 100),
    Size = UDim2.new(0, 92, 0, 28),
    Font = Enum.Font.GothamBold,
    Text = "HTTPspy",
    TextColor3 = GREEN,
    TextSize = 12,
    Visible = false,
    AutoButtonColor = false,
}, gui)
corner(pill, 14)
stroke(pill, LINE)

minimizeButton.MouseButton1Click:Connect(function()
    main.Visible = false
    pill.Visible = true
end)
pill.MouseButton1Click:Connect(function()
    main.Visible = true
    pill.Visible = false
end)
closeButton.MouseButton1Click:Connect(uninstall)

rebuild()
print("[HTTPspy] installed — request/syn.request/http_request/game:HttpGet")
