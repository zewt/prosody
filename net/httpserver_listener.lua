-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- 
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--



local connlisteners_register = require "net.connlisteners".register;
local new_connection = require "net.httpserver".new_connection;
local request_reader = require "net.httpserver".request_reader;

local connections = {}; -- Open connections

local httpserver = { default_port = 80, default_mode = "*a" };

function httpserver.onincoming(conn, data)
	local connection = connections[conn];

	if not connection then
		connection = new_connection(conn);
		connections[conn] = connection;
		
		-- If using HTTPS, connection is secure
		if conn:ssl() then
			connection.secure = true;
		end
	end

	if data and data ~= "" then
		request_reader(connection, data);
	end
end

function httpserver.ondisconnect(conn, err)
	local connection = connections[conn];
	if connection and not connection.destroyed then
		connection.conn = nil;
		request_reader(connection, nil);
	end
	connections[conn] = nil;
end

connlisteners_register("httpserver", httpserver);
