-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- 
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--


local httpserver = require "net.httpserver";
local os = os;
local string = string;
local lfs;
pcall(function () lfs = require "lfs" end)

local open = io.open;
local t_concat = table.concat;

local http_base = config.get("*", "core", "http_path") or "www_files";
local http_log = config.get("*", "core", "http_log")

local response_400 = { status = "400 Bad Request", body = "<h1>Bad Request</h1>Sorry, we didn't understand your request :(" };
local response_403 = { status = "403 Forbidden", body = "<h1>Forbidden</h1>You don't have permission to view the contents of this directory :(" };
local response_404 = { status = "404 Not Found", body = "<h1>Page Not Found</h1>Sorry, we couldn't find what you were looking for :(" };

-- TODO: Should we read this from /etc/mime.types if it exists? (startup time...?)
local mime_map = {
	html = "text/html";
	htm = "text/html";
	xml = "text/xml";
	xsl = "text/xml";
	txt = "text/plain; charset=utf-8";
	js = "text/javascript";
	css = "text/css";
};

local logfile

local function preprocess_path(path)
	if path:sub(1,1) ~= "/" then
		path = "/"..path;
	end
	local level = 0;
	for component in path:gmatch("([^/]+)/") do
		if component == ".." then
			level = level - 1;
		elseif component ~= "." then
			level = level + 1;
		end
		if level < 0 then
			return nil;
		end
	end
	return path;
end

local function log_common(request, status, size)
	if not logfile then
           return
        end

	local ip = request.handler:ip();
	local req = string.format("%s %s HTTP/%s", request.method, request.url.path, request.httpversion);
	local date = os.date("%d/%m/%Y:%H:%M:%S %z");
	size = size or "-";
	local ent = string.format("%s - - [%s] \"%s\" %d %s\n", ip, date, req, status, tostring(size))

        logfile:write(ent)
end

local function reopen_log_files()
	if logfile then
		logfile:close()
	end

	logfile = open(http_log, "a")
end

function serve_file(request, path)
	if lfs then
		local stat = lfs.attributes(http_base..path) or {}
		if stat.mode == "directory" then
			return serve_file(request, path.."/index.html")
		end
	end
	local f, err = open(http_base..path, "rb");
	if not f then
		log_common(request, 404);
		return response_404;
	end
	local data = f:read("*a");
	f:close();
	if not data then
		return response_403;
	end
	local ext = path:match("%.([^.]*)$");
	local mime = mime_map[ext]; -- Content-Type should be nil when not known
        log_common(request, 200, #data);
	return {
		headers = { ["Content-Type"] = mime; };
		body = data;
	};
end

local function handle_file_request(method, body, request)
	local path = preprocess_path(request.url.path);
	if not path then
		log_common(request, 400);
		return response_400;
	end
	path = path:gsub("^/[^/]+", ""); -- Strip /files/
	return serve_file(request, path);
end

local function handle_default_request(method, body, request)
	local path = preprocess_path(request.url.path);
	if not path then
		log_common(request, 400);
		return response_400;
	end
	return serve_file(request, path);
end

local function setup()
	local ports = config.get(module.host, "core", "http_ports") or { 5280 };
	httpserver.set_default_handler(handle_default_request);
	httpserver.new_from_config(ports, handle_file_request, { base = "files" });
	if http_log then
		reopen_log_files()
		eventmanager.add_event_hook("reopen-log-files", reopen_log_files)
	end
end
if prosody.start_time then -- already started
	setup();
else
	prosody.events.add_handler("server-started", setup);
end
