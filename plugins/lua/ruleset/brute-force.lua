-- Copyright (C) 2006 G Ramon Gomez <gene at gomezbrothers dot com>
-- Copyright (C) 2008 PreludeIDS Technologies <info@prelude-ids.com>
-- All Rights Reserved.
--
-- This file is part of the Prelude-Correlator program.
--
-- This program is free software; you can redistribute it and/or modify
-- it under the terms of the GNU General Public License as published by
-- the Free Software Foundation; either version 2, or (at your option)
-- any later version.
--
-- This program is distributed in the hope that it will be useful,
-- but WITHOUT ANY WARRANTY; without even the implied warranty of
-- MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
-- GNU General Public License for more details.
--
-- You should have received a copy of the GNU General Public License
-- along with this program; see the file COPYING.  If not, write to
-- the Free Software Foundation, 675 Mass Ave, Cambridge, MA 02139, USA.

is_failed_auth = INPUT:match("alert.classification.text", "[Ll]ogin|[Aa]uthentication",
                             "alert.assessment.impact.completion", "failed")


result = INPUT:match("alert.source(*).node.address(*).address", "(.+)",
                     "alert.target(*).node.address(*).address", "(.+)");

if is_failed_auth and result then
    for i, source in ipairs(result[1]) do
        for i, target in ipairs(result[2]) do

            ctx = Context.update("BRUTE_ST_" .. source .. target, { expire = 2, threshold = 5 })
            ctx:set("alert.source(>>)", INPUT:get("alert.source"))
            ctx:set("alert.target(>>)", INPUT:get("alert.target"))
            ctx:set("alert.correlation_alert.alertident(>>).alertident", INPUT:get("alert.messageid"))
            ctx:set("alert.correlation_alert.alertident(-1).analyzerid", INPUT:getAnalyzerid())

            if ctx:CheckAndDecThreshold() then
                ctx:set("alert.classification.text", "Brute force attack")
                ctx:set("alert.correlation_alert.name", "Multiple failed login")
                ctx:set("alert.assessment.impact.severity", "high")
                ctx:set("alert.assessment.impact.description",
                        "Multiple failed attempts have been made to login to a user account")
                ctx:alert()
                ctx:del()
            end
        end
    end
end

-- Detect brute force attempt by user
-- This rule looks for all classifications that match login or authentication
-- attempts, and detects when they exceed a certain threshold.

userid = INPUT:match("target(*).user.user_id(*).name", "(.+)");

if is_failed_auth and userid then
    for i, user in ipairs(userid[1]) do
        ctx = ctx.update("BRUTE_U_" .. user, { expire = 120, threshold = 2 })
        ctx:Set("alert.source(>>)", INPUT:Get("alert.source"))
        ctx:Set("alert.target(>>)", INPUT:Get("alert.target"))
        ctx:Set("alert.correlation_alert.alertident(>>).alertident", INPUT:get("alert.messageid"))
        ctx:Set("alert.correlation_alert.alertident(-1).analyzerid", INPUT:getAnalyzerid())

        if ctx:CheckAndDecThreshold() then
            ctx:Set("alert.classification.text", "Brute force attack")
            ctx:Set("alert.correlation_alert.name", "Multiple failed login")
            ctx:Set("alert.impact.severity", "high")
            ctx:Set("alert.impact.description", "Multiple failed attempts have been made to login to a user account")

            ctx:alert()
            ctx:del()
        end
    end
end
