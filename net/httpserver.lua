-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- 
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--


local server = require "net.server"
local url_parse = require "socket.url".parse;
local httpstream_new = require "util.httpstream".new;

local connlisteners_start = require "net.connlisteners".start;
local connlisteners_get = require "net.connlisteners".get;
local listener;

local t_insert, t_concat = table.insert, table.concat;
local tonumber, tostring, pairs, ipairs, type = tonumber, tostring, pairs, ipairs, type;
local xpcall = xpcall;
local debug_traceback = debug.traceback;

local urlencode = function (s) return s and (s:gsub("%W", function (c) return ("%%%02x"):format(c:byte()); end)); end

local log = require "util.logger".init("httpserver");

local http_servers = {};

module "httpserver"

local default_handler;

local function send_response(request, response)
	if request.handled then return; end
	request.handled = true;

	local connection_close = true;
	local response_http_version = "HTTP/1.0";
	if request.httpversion == "1.1" then
		response_http_version = "HTTP/1.1";
		connection_close = (request.headers["connection"] == "close");
	end
	log("debug", "HTTP version is " .. response_http_version);
	log("debug", "HTTP keepalives are " .. (connection_close and "disabled" or "enabled"));

	-- Write status line
	local body, headers;
	if response.body or response.headers then
		body = response.body and tostring(response.body);
		headers = response.headers;
	else
		-- Response we have is just a string (the body)
		log("debug", "Sending 200 response to %s", request.id or "<none>");
		headers = {
			["Content-Type"] = "text/html",
			["Content-Length"] = #response
		};
		body = response;
	end

	log("debug", "Sending response to %s", request.id);
	local resp = { response_http_version .. " "..(response.status or "200 OK").."\r\n" };
	if headers then
		for k, v in pairs(headers) do
			t_insert(resp, k..": "..v.."\r\n");
		end
	end
	if connection_close and response_http_version == "HTTP/1.1" then
		t_insert(resp, "Connection: close\r\n");
	end
	if body and not (headers and headers["Content-Length"]) then
		t_insert(resp, "Content-Length: "..#body.."\r\n");
	end
	t_insert(resp, "\r\n");

	if body and request.method ~= "HEAD" then
		t_insert(resp, body);
	end
	request.write(t_concat(resp));

	if connection_close then
		request:destroy();
	end
end

local function call_callback(request, err)
	local callback = request.callback;
	if not callback and request.path then
		local path = request.url.path;
		local base = path:match("^/([^/?]+)");
		if not base then
			base = path:match("^http://[^/?]+/([^/?]+)");
		end
		
		callback = (request.server and request.server.handlers[base]) or default_handler;
	end
	if callback then
		local _callback = callback;
		function callback(method, body, request)
			local ok, result = xpcall(function() return _callback(method, body, request) end, debug_traceback);
			if ok then return result; end
			log("error", "Error in HTTP server handler: %s", result);
			if not request.handled then
				return {
					status = "500 Internal Server Error";
					headers = { ["Content-Type"] = "text/plain" };
					body = "There was an error processing your request. See the error log for more details.";
				};
			end
		end
		if err then
			log("debug", "Request error: "..err);
			if not callback(nil, err, request) then
				destroy_request(request);
			end
			return;
		end
		
		local response = callback(request.method, request.body and t_concat(request.body), request);
		if response then
			if response == true and not request.destroyed then
				-- Keep connection open, we will reply later
				log("debug", "Request %s left open, on_destroy is %s", request.id, tostring(request.on_destroy));
			elseif response ~= true then
				-- Assume response
				send_response(request, response);
				destroy_request(request);
			end
		else
			log("debug", "Request handler provided no response, destroying request...");
			-- No response, close connection
			destroy_request(request);
		end
	end
end

local function request_reader(request, data)
	if not request.parser then
		local function success_cb(r)
			for k,v in pairs(request) do r[k] = v; end
			r.url = url_parse(r.path);
			r.url.path = r.url.path and r.url.path:gsub("%%(%x%x)", function(x) return x.char(tonumber(x, 16)) end);
			r.body = { r.body };
			call_callback(r);
		end
		local function error_cb(r)
			call_callback(connection, r or "connection-closed");
			destroy_connection(connection);
		end
		request.parser = httpstream_new(success_cb, error_cb);
	end
	request.parser:feed(data);
end

-- The default handler for requests
default_handler = function (method, body, request)
	log("debug", method.." request for "..tostring(request.path) .. " on port "..request.handler:serverport());
	return { status = "404 Not Found",
			headers = { ["Content-Type"] = "text/html" },
			body = "<html><head><title>Page Not Found</title></head><body>Not here :(</body></html>" };
end


function new_request(handler)
	return { handler = handler, conn = handler,
			write = function (...) return handler:write(...); end, state = "request",
			server = http_servers[handler:serverport()],
			send = send_response,
			destroy = destroy_request,
			id = tostring{}:match("%x+$")
			 };
end

function destroy_request(request)
	log("debug", "Destroying request %s", request.id);
	listener = listener or connlisteners_get("httpserver");
	if not request.destroyed then
		request.destroyed = true;
		if request.on_destroy then
			log("debug", "Request has destroy callback");
			request.on_destroy(request);
		else
			log("debug", "Request has no destroy callback");
		end
		request.handler:close()
		if request.conn then
			listener.ondisconnect(request.conn, "closed");
		end
	end
end

function new(params)
	local http_server = http_servers[params.port];
	if not http_server then
		http_server = { handlers = {} };
		http_servers[params.port] = http_server;
		-- We weren't already listening on this port, so start now
		connlisteners_start("httpserver", params);
	end
	if params.base then
		http_server.handlers[params.base] = params.handler;
	end
end

function set_default_handler(handler)
	default_handler = handler;
end

function new_from_config(ports, handle_request, default_options)
	if type(handle_request) == "string" then -- COMPAT with old plugins
		log("warn", "Old syntax of httpserver.new_from_config being used to register %s", handle_request);
		handle_request, default_options = default_options, { base = handle_request };
	end
	ports = ports or {5280};
	for _, options in ipairs(ports) do
		local port = default_options.port or 5280;
		local base = default_options.base;
		local ssl = default_options.ssl or false;
		local interface = default_options.interface;
		if type(options) == "number" then
			port = options;
		elseif type(options) == "table" then
			port = options.port or port;
			base = options.path or base;
			ssl = options.ssl or ssl;
			interface = options.interface or interface;
		elseif type(options) == "string" then
			base = options;
		end
		
		if ssl then
			ssl.mode = "server";
			ssl.protocol = "sslv23";
			ssl.options = "no_sslv2";
		end
		
		new{ port = port, interface = interface,
			base = base, handler = handle_request,
			ssl = ssl, type = (ssl and "ssl") or "tcp" };
	end
end

_M.request_reader = request_reader;
_M.send_response = send_response;
_M.urlencode = urlencode;

return _M;
