-- Copyright (C) 2006-2008 PreludeIDS Technologies. All Rights Reserved.
-- Author: Yoann Vandoorselaere <yoann.v@prelude-ids.com>
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


-- Firewall correlation (1 of 2)
-- This rule detects packet denials and resets any contexts that may have been
-- created regarding events attached to this packet.  It sets a timer for the
-- next 10 seconds for other events that might match the criterea.

function firewall(INPUT)

local isdrop = INPUT:match("alert.classification.text", "[Pp]acket [Dd]ropped|[Dd]enied")
local result = INPUT:get("alert.source(0).node.address(0).address",
                         "alert.source(0).service.port",
                         "alert.target(0).node.address(0).address",
                         "alert.target(0).service.port")

local ctxname
local source, sport, target, dport = result[1], result[2] or "", result[3], result[4] or ""

if source and target then
    ctxname = source .. sport .. target .. dport
end

if isdrop and source and target then
    Context.update(ctxname, { expire = 10 })
end


-- Firewall correlation (2 of 2)
-- This rule begins a timer for every event that contains a source and a target
-- address which has not been matched by an observed packet denial.  If a packet
-- denial is not observed in the next 10 seconds, an event alert is generated.

if not isdrop and source and target then
    if not Context.get(ctxname) then
        local ctx = Context.new(ctxname, { expire = 10, alert_on_expire = true })
        ctx:set("alert.source", INPUT:getraw("alert.source"))
        ctx:set("alert.target", INPUT:getraw("alert.target"))
        ctx:set("alert.assessment", INPUT:getraw("alert.assessment"))
        ctx:set("alert.classification", INPUT:getraw("alert.classification"))
        ctx:set("alert.correlation_alert.name", "Events to firewall correlation")
        ctx:set("alert.correlation_alert.alertident(0).analyzerid", INPUT:getAnalyzerid())
        ctx:set("alert.correlation_alert.alertident(0).alertident", INPUT:getraw("alert.messageid"))
    end
end

end -- function firewall(INPUT)
