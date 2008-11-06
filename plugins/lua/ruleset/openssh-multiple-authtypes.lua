-- Copyright (C) 2008 INL <inl@inl.fr>
-- Copyright (C) 2008 S. Tricaud <stricaud@inl.fr>
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

--
-- This rule checks for whether a given user
-- authenticates in multiple ways: password and passphrase
-- If so -> alert.
--
function openssh_multiple_authtypes(INPUT)

local success_sshauth = INPUT:match("alert.assessment.impact.completion", "succeeded",
                               "alert.analyzer(-1).manufacturer","OpenSSH",
                               "alert.target(*).user.user_id(*).name", "(.+)",
                               "alert.target(*).node.address(*).address", "(.+)")

if success_sshauth and success_sshauth[1] ~= nil and success_sshauth[2] ~= nil then
    for i, username in ipairs(success_sshauth[1]) do
        for i, target in ipairs(success_sshauth[2]) do
            local ad_meaning = INPUT:get("alert.additional_data(*).meaning")
            if ad_meaning then
                for i, ad_string in ipairs(ad_meaning) do
                    if ad_string == "Authentication method" then
                        local authpath = "alert.additional_data(" .. tostring(i-1) .. ").data"
                        local authtype = INPUT:get(authpath)
                        local ctx = Context.update("SSH_MAT_" .. target .. username, { threshold = 1 })
                        ctx:set("alert.source(>>)", INPUT:getraw("alert.source"))
                        ctx:set("alert.target(>>)", INPUT:getraw("alert.target"))
                        ctx:set("alert.correlation_alert.alertident(>>).alertident", INPUT:getraw("alert.messageid"))
                        ctx:set("alert.correlation_alert.alertident(-1).analyzerid", INPUT:getAnalyzerid())
                        if not ctx.authtype then
                            ctx.authtype = authtype
                        else
                            if ctx.authtype ~= authtype then
                                ctx:set("alert.classification.text", "Multiple authentication methods")
                                ctx:set("alert.correlation_alert.name", "Multiple authentication methods")
                                ctx:set("alert.assessment.impact.severity", "medium")
                                ctx:set("alert.assessment.impact.description",
                                        "Multiple ways of authenticating a single user have been found over SSH. If passphrase is the only allowed method, make sure you disable passwords.")
                                ctx:alert()
                               ctx:del()
                            end -- if ctx.authtype ~= authtype then
                        end -- if not ctx.authtype then
                    end -- if ad_string == "Authentication method" then
                end -- for i, ad_string in ipairs(ad_meaning) do
            end -- if ad_meaning then
        end -- for i, target in ipairs(success_sshauth[2]) do
    end -- for i, username in ipairs(success_sshauth[1]) do
end -- if success_sshauth and success_sshauth[1] ~= nil and success_sshauth[2] ~= nil then

end -- function ssh_multiple_authtypes(INPUT)

