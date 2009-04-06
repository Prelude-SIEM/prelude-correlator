-- Copyright (C) 2009 INL <inl@inl.fr>
-- Copyright (C) 2009 S. Tricaud <stricaud@inl.fr>
-- Copyright (C) 2009 PreludeIDS Technologies <info@prelude-ids.com>
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
--

local DSHIELD_RELOAD = 7 * 24 * 60 * 60
local DSHIELD_URL = "http://www.dshield.org/ipsascii.html?limit=10000"

function load_dshield_data(fname, attr)
        local cnt = 0
        local iphash = {}

        fd = io.input(fname)

        for line in fd:lines() do
                if not string.find(line,"^#") then
                        val = string.split(line, "\t")
                        iphash[val[1]] = true
                        cnt = cnt + 1
                end
        end

        Timer.new(DSHIELD_RELOAD - (os.time() - attr.modification), retrieve_dshield_data)

        return iphash
end


function retrieve_dshield_data()
        local lfs = require("lfs")
        local http = require("socket.http")
        local fname = PRELUDE_CORRELATOR_LIB_DIR .. "/dshield.dat"

        local attr = lfs.attributes(fname)
        if attr and (os.time() - attr.modification) < DSHIELD_RELOAD then
                return load_dshield_data(fname, attr)
        end

        info("Downloading host list from dshield, this might take some time...")
        body = http.request(DSHIELD_URL)
        info("Downloading done, processing data.")

        fd = io.output(fname)
        fd:write(body)
        fd:close(body)

        return load_dshield_data(fname, attr)
end


iphash = retrieve_dshield_data()


function normalize_ip(ipaddr)
        quads = string.split(ipaddr, ".")
        return string.format("%.3d.%.3d.%.3d.%.3d", quads[1], quads[2], quads[3], quads[4])
end


function dshield(INPUT)

local result = INPUT:get("alert.source(*).node.address(*).address")
if result then
        for i, source in ipairs(result) do
                if iphash[normalize_ip(source)] then
                        local ctx = Context.update("DSHIELD_DB_" .. source, { threshold = 1 })
                        ctx:set("alert.source(>>)", INPUT:getraw("alert.source"))
                        ctx:set("alert.target(>>)", INPUT:getraw("alert.target"))
                        ctx:set("alert.correlation_alert.alertident(>>).alertident", INPUT:getraw("alert.messageid"))
                        ctx:set("alert.correlation_alert.alertident(-1).analyzerid", INPUT:getAnalyzerid())
                        ctx:set("alert.classification.text", "IP source matching Dshield database")
                        ctx:set("alert.correlation_alert.name", "IP source matching Dshield database")
                        ctx:set("alert.assessment.impact.description", "Dshield gather IP addresses tagged from firewall logs drops")
                        ctx:set("alert.assessment.impact.severity", "high")
                        ctx:alert()
                        ctx:del()
                end
        end
end

end -- function dshield_match(INPUT)

