--[[
Additional IDMEF class function
]]

function IDMEF:getAnalyzerid()
        local list = self:get("alert.analyzer(*).analyzerid")
        local id

        for i, value in ipairs(list) do
            id = value
        end

        return id
end




--[[
Context class
]]

__C = {}
Context = {}
Context.__index = Context

function _del_context_(name)
        c = Context.get(name)

        if c._alert_on_expire then
            c:alert()
        end

        c:del()
end

function Context:del()
    self._timer = nil
    self._idmef = nil
    __C[self._name] = nil
end

function Context:CheckAndDecThreshold()
    self._threshold = self._threshold - 1
    if self._threshold == 0 then
        return true
    else
        return false
    end
end

function Context:set(path, value)
    if value ~= nil then
        return self._idmef:set(path, value)
    end
end

function Context:getIDMEF(...)
    return self._idmef:get(unpack(arg))
end

function Context:alert()
    self._idmef:alert()
end

function Context.get(name)
    return __C[name]
end


function Context.new(name, options)
    local ctx = {}

    setmetatable(ctx, Context)

    ctx._name = name
    ctx._idmef = IDMEF.new()
    ctx._expire = options["expire"]
    ctx._threshold = options["threshold"]
    ctx._alert_on_expire = false
    __C[name] = ctx

    if options["alert_on_expire"] then
        ctx._alert_on_expire = true
    end

    if ctx._expire ~= nil then
        ctx._timer = Timer.new(name)
        ctx._timer:start(ctx._expire)
    end

    return ctx
end

function Context.update(name, options)
        elem = Context.get(name)
        if elem == nil then
            elem = Context.new(name, options)

        elseif elem._timer then
            elem._timer:reset(options["expire"])
        end

        return elem
end


-- Utility function
--
function _table.dump(depth, result)
   for i,v in pairs(result) do
        if type(v) == "table" then
                for x=0,depth-1 do io.write("\t") end io.write(i, " table") print(":")
                _table_dump(depth + 1, v)
        else
                for x=0,depth-1 do io.write("\t") end print(i, v or "<nil>")
        end
   end
end


function table.dump(result)
    print "***********************"
    if result then
        _table.dump(0, result)
    else
        print("table is nil")
    end
    print "***********************"
end


function table.find(list, what)
    for key, value in ipairs(list) do
        if value == what then
            return true
        end
    end

    return false
end


function string.split(str, pattern)
        local ret = {}
        local start = 1
        local plen = string.len(pattern)

        while true do
                local pos = string.find(str, pattern, start, true)
                if not pos then
                        break
                end

                table.insert(ret, string.sub(str, start, pos - 1))
                start = pos + plen
        end

        table.insert(ret, string.sub(str, start))
        return ret
end

