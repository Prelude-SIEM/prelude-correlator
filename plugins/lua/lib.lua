-- class.lua
-- Compatible with Lua 5.1 (not 5.0).
function class(base, ctor)
    local c = {}     -- a new class instance

    if not ctor and type(base) == 'function' then
       ctor = base
       base = nil
    elseif type(base) == 'table' then
        -- our new class is a shallow copy of the base class!
        for i, v in pairs(base) do
            c[i] = v
        end

        c._base = base
    end

    -- the class will be the metatable for all its objects,
    -- and they will look up their methods in it.
    c.__index = c

    -- expose a ctor which can be called by <classname>(<args>)
    local mt = {}
    mt.__call = function(class_tbl, ...)
                    local obj = {}
                    setmetatable(obj,c)

                    if ctor then
                        ctor(obj,...)
                    else
                        -- make sure that any stuff from the base class is initialized!
                        if base and base.init then
                            base.init(obj, ...)
                        end
                    end

                    return obj
                end

    c.init = ctor
    c.is_a = function(self, klass)
                 local m = getmetatable(self)

                 while m do
                     if m == klass then return true end
                     m = m._base
                 end

             return false
             end

    setmetatable(c, mt)
    return c
end


__C = {}


Context = class(function(ctx, name, options)
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
                end)


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

function Context:alert()
    self._idmef:alert()
end

function Context.get(name)
    return __C[name]
end

function Context.update(name, options)
        elem = Context.get(name)
        if elem == nil then
            elem = Context(name, options)

        elseif elem._timer then
            elem._timer:reset(options["expire"])
        end

        return elem
end


function dump(depth, result)
   for i,v in pairs(result) do
        if type(v) == "table" then
                for x=0,depth-1 do io.write("\t") end io.write(i, " table") print(":")
                dump(depth + 1, v)
        else
                for x=0,depth-1 do io.write("\t") end print(i, v)
        end
   end
end

