-- Copyright (C) 2006 G Ramon Gomez <gene at gomezbrothers dot com>
-- Copyright (C) 2006-2008 PreludeIDS Technologies <yoann.v@prelude-ids.com>
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


function worm(INPUT)

-- This rule looks for events against a host, records the messageid, then sets
-- a timer of 600 seconds.   If the host then replays the event against
-- other hosts multiple times, an event is generated.


local result = INPUT:get("alert.classification.text",
                         "alert.source(*).node.address(*).address",
                         "alert.target(*).node.address(*).address")

if result and result[1] and result[2] and result[3] then
-- Create context for classification combined with all the target.

    for i, target in ipairs(result[3]) do
        ctx = Context.update("WORM_HOST_" .. result[1] .. target, { expire = 300, threshold = 5 })
    end

    for i, source in ipairs(result[2]) do
        -- We are trying to see whether a previous target is now attacking other hosts
        -- thus, we check whether a context exist with this classification combined to
        -- this source.

        ctx = Context.get("WORM_HOST_" .. result[1] .. source)
        if ctx then
            ctx:set("alert.source(>>)", INPUT:getraw("alert.source"))
            ctx:set("alert.target(>>)", INPUT:getraw("alert.target"))
            ctx:set("alert.correlation_alert.alertident(>>).alertident", INPUT:getraw("alert.messageid"))
            ctx:set("alert.correlation_alert.alertident(-1).analyzerid", INPUT:getAnalyzerid())

            -- Increase and check the context threshold.
            if ctx:CheckAndDecThreshold() then
                ctx:set("alert.classification.text", "Possible Worm Activity")
                ctx:set("alert.correlation_alert.name", "Source host repeating actions taken against it recently")
                ctx:set("alert.assessment.impact.severity", "high")
                ctx:set("alert.assessment.impact.description", source .. "has repeated actions taken against it recently at least 5 times. It may have been infected with a worm.")
                ctx:alert()
                ctx:del()
            end
        end
    end
end

end -- function worm(INPUT)
