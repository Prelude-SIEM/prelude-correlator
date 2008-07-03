--
-- Copyright (C) 2008 PreludeIDS Technologies. All Rights Reserved.
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
--

function business_hour(INPUT)

local t = INPUT:get("alert.create_time")
local is_succeeded = INPUT:match("alert.assessment.impact.completion", "succeeded")

-- Run this code only on saturday (1) and sunday (6), or from 6:00pm to 9:00am.
if is_succeeded and (t.wday == 1 or t.wday == 6 or t.hour < 9 or t.hour > 18) then
	local ca = IDMEF.new()

        ca:set("alert.source", INPUT:getraw("alert.source"))
        ca:set("alert.target", INPUT:getraw("alert.target"))
        ca:set("alert.classification", INPUT:getraw("alert.classification"))
        ca:set("alert.correlation_alert.alertident(>>).alertident", INPUT:getraw("alert.messageid"))
        ca:set("alert.correlation_alert.alertident(-1).analyzerid", INPUT:getAnalyzerid())
        ca:set("alert.correlation_alert.name", "Critical system activity on day off")
	ca:alert()
end

end
