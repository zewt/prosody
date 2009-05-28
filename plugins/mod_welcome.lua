-- Prosody IM v0.4
-- Copyright (C) 2008-2009 Matthew Wild
-- Copyright (C) 2008-2009 Waqas Hussain
-- 
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

local config = require "core.configmanager";

local host = module:get_host();
local welcome_text = config.get("*", "core", "welcome_message") or "Hello $user, welcome to the $host IM server!";

local st = require "util.stanza";

module:add_event_hook("user-registered", 
	function (user)
		local welcome_stanza = 
			st.message({ to = user.username.."@"..user.host, from = host })
				:tag("body"):text(welcome_text:gsub("$(%w+)", user));
		core_route_stanza(hosts[host], welcome_stanza);
		module:log("debug", "Welcomed user %s@%s", user.username, user.host);
	end);