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


result = match("alert.source(*).node.address(*).address", "(.+)",
               "alert.target(*).node.address(*).address", "(.+)",
   --            "alert.classification.text", "[Ll]ogin|[Aa]uthentication",
   --            "alert.assessment.impact.completion", "failed",
               "alert.messageid", "(.+)",
               "alert.analyzer(*).analyzerid", "(.*)");

for k, s in ipairs(result[1]) do
for k2, source in ipairs(s) do
    for i, t in ipairs(result[2]) do for i2, target in ipairs(t) do

        ctx = Context.update("BRUTE_ST_" .. source .. target, { expire = 2, threshold = 5 })
        ctx:set("alert.source(>>)", INPUT:get("alert.source"))
        ctx:set("alert.target(>>)", INPUT:get("alert.target"))
        ctx:set("alert.correlation_alert.alertident(>>).alertident", result[3])
        ctx:set("alert.correlation_alert.alertident(-1).analyzerid", result[4][table.getn(result[4])])

        if ctx:CheckAndDecThreshold() then
            ctx:set("alert.classification.text", "Brute force attack")
            ctx:set("alert.correlation_alert.name", "Multiple failed login")
            ctx:set("alert.assessment.impact.severity", "high")
            ctx:set("alert.assessment.impact.description", "Multiple failed attempts have been made to login to a user account")

            ctx:alert()
            ctx:del()
        end
    end end
end end


-- Detect brute force attempt by user
-- This rule looks for all classifications that match login or authentication
-- attempts, and detects when they exceed a certain threshold.

result = match("classification.text", "[Ll]ogin|[Aa]uthentication",
               "assessment.impact.completion", "failed",
               "target(*).user.user_id(*).name", "(.+)",
               "messageid", "(.+)",
               "analyzer(*).analyzerid", "(.*)");

if #result > 0 then
for k, target in ipairs(result[1]) do for i, user in ipairs(target) do
    ctx = ctx.update("BRUTE_U_" .. user, { expire = 120, threshold = 2 })
    ctx:Set("alert.source(>>)", INPUT:Get("alert.source"))
    ctx:Set("alert.target(>>)", INPUT:Get("alert.target"))
    ctx:Set("alert.correlation_alert.alertident(>>).alertident", result[2])
    ctx:Set("alert.correlation_alert.alertident(-1).analyzerid", result[3][table.getn(result[3])])

    if ctx:CheckAndDecThreshold() then
        ctx:Set("alert.classification.text", "Brute force attack")
        ctx:Set("alert.correlation_alert.name", "Multiple failed login")
        ctx:Set("alert.impact.severity", "high")
        ctx:Set("alert.impact.description", "Multiple failed attempts have been made to login to a user account")

        ctx:alert()
        ctx:del()
    end
end end
end
