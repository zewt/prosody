-- Prosody IM
-- Copyright (C) 2008-2010 Matthew Wild
-- Copyright (C) 2008-2010 Waqas Hussain
-- 
-- This project is MIT/X11 licensed. Please see the
-- COPYING file in the source package for more information.
--

module.host = "*" -- Global module

local hosts = _G.hosts;
local lxp = require "lxp";
local new_xmpp_stream = require "util.xmppstream".new;
local httpserver = require "net.httpserver";
local sm = require "core.sessionmanager";
local sm_destroy_session = sm.destroy_session;
local new_uuid = require "util.uuid".generate;
local fire_event = prosody.events.fire_event;
local core_process_stanza = core_process_stanza;
local st = require "util.stanza";
local logger = require "util.logger";
local log = logger.init("mod_bosh");
local timer = require "util.timer";

local xmlns_streams = "http://etherx.jabber.org/streams";
local xmlns_xmpp_streams = "urn:ietf:params:xml:ns:xmpp-streams";
local xmlns_bosh = "http://jabber.org/protocol/httpbind"; -- (hard-coded into a literal in session.send)

local stream_callbacks = {
	stream_ns = xmlns_bosh, stream_tag = "body", default_ns = "jabber:client" };

local BOSH_DEFAULT_HOLD = tonumber(module:get_option("bosh_default_hold")) or 3;
local BOSH_DEFAULT_INACTIVITY = tonumber(module:get_option("bosh_max_inactivity")) or 60;
local BOSH_DEFAULT_POLLING = tonumber(module:get_option("bosh_max_polling")) or 5;
local BOSH_DEFAULT_REQUESTS = tonumber(module:get_option("bosh_max_requests")) or 5;

-- The maximum number of responses to store for rerequesting.  Clients shouldn't need
-- to request more requests than they can open simultaneously, so keep up to REQUESTS.
local response_history_size = BOSH_DEFAULT_REQUESTS;

-- The number of requests in the future clients can send.  Within this threshold,
-- future requests will be buffered until previous requests arrive.
local request_buffer_size = BOSH_DEFAULT_REQUESTS;

local consider_bosh_secure = module:get_option_boolean("consider_bosh_secure");

local default_headers = { ["Content-Type"] = "text/xml; charset=utf-8" };

local cross_domain = module:get_option("cross_domain_bosh");
if cross_domain then
	default_headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
	default_headers["Access-Control-Allow-Headers"] = "Content-Type";
	default_headers["Access-Control-Max-Age"] = "7200";

	if cross_domain == true then
		default_headers["Access-Control-Allow-Origin"] = "*";
	elseif type(cross_domain) == "table" then
		cross_domain = table.concat(cross_domain, ", ");
	end
	if type(cross_domain) == "string" then
		default_headers["Access-Control-Allow-Origin"] = cross_domain;
	end
end

local trusted_proxies = module:get_option_set("trusted_proxies", {"127.0.0.1"})._items;

local function get_ip_from_request(request)
	local ip = request.handler:ip();
	local forwarded_for = request.headers["x-forwarded-for"];
	if forwarded_for then
		forwarded_for = forwarded_for..", "..ip;
		for forwarded_ip in forwarded_for:gmatch("[^%s,]+") do
			if not trusted_proxies[forwarded_ip] then
				ip = forwarded_ip;
			end
		end
	end
	return ip;
end

local t_insert, t_remove, t_concat = table.insert, table.remove, table.concat;
local os_time = os.time;

local sessions = {};
local inactive_sessions = {}; -- Sessions which have no open requests

-- Used to respond to idle sessions (those with waiting requests)
local waiting_requests = {};
function on_destroy_connection(request)
	waiting_requests[request] = nil;
	local session = sessions[request.sid];
	if session then
		local function remove_request(t)
			for i,r in ipairs(t) do
				if r == request then
					t_remove(t, i);
					return;
				end
			end
		end
		local inbound_requests = session.inbound_requests;
		remove_request(session.inbound_requests);

		local outbound_requests = session.outbound_requests;
		remove_request(session.outbound_requests);
		
		-- If this session now has no requests open, mark it as inactive
		if #inbound_requests == 0 and #outbound_requests == 0 and session.bosh_max_inactive and not inactive_sessions[session] then
			inactive_sessions[session] = os_time();
			(session.log or log)("debug", "BOSH session marked as inactive at %d", inactive_sessions[session]);
		end
	end
end

local function terminateWithError(request, session, errorCondition)
	local item_not_found_response = { headers = default_headers,
		body = "<body type='terminate' condition='" .. errorCondition .. "' xmlns='http://jabber.org/protocol/httpbind'/>"
	};

	request:send(item_not_found_response);
	if session ~= nil then
		session:close();
	end
end

local process_request;
local create_session;
function handle_request(method, body, request)
	if (not body) or request.method ~= "POST" then
		if request.method == "OPTIONS" then
			local headers = {};
			for k,v in pairs(default_headers) do headers[k] = v; end
			headers["Content-Type"] = nil;
			return { headers = headers, body = "" };
		else
			return "<html><body>You really don't look like a BOSH client to me... what do you want?</body></html>";
		end
	end
	if not method then
		log("debug", "Request %s suffered error %s", tostring(request.id), body);
		return;
	end
	--log("debug", "Handling new request %s: %s\n----------", request.id, tostring(body));
	request.notopen = true;
	request.log = log;
	request.on_destroy = on_destroy_connection;
	request.stanzas = {};
	
	local stream = new_xmpp_stream(request, stream_callbacks);
	-- stream:feed() calls the stream_callbacks, so all stanzas in
	-- the body are processed in this next line before it returns.
	stream:feed(body);

	if not request.closed then
		log("warn", "Invalid request");
		terminateWithError(request, nil, "bad-request");
		return true;
	end

	if not request.attr.sid then
		create_session(request);
		return true;
	end

	local sid = request.attr.sid;
	local session = sessions[sid];
	if not session then
		-- Unknown sid
		log("info", "Client tried to use sid '%s' which we don't know about", sid);
		request:send{ headers = default_headers, body = tostring(st.stanza("body", { xmlns = xmlns_bosh, type = "terminate", condition = "item-not-found" })) };
		return true;
	end
	
	if request.attr.type == "terminate" then
		-- Client wants to end this session, which we'll do
		-- after processing any stanzas in this request
		session.bosh_terminate = true;
	end

	-- Check that the RID of this request isn't too far in the future (sec14.2).
	if request.rid - session.previous_rid_processed - 1 > request_buffer_size then
		session.log("warn", "rid too large; too many requests were lost. Last rid: %d New rid: %s", session.previous_rid_processed, request.rid);
		terminateWithError(request, session, "item-not-found");
		return;
	end

	local function find_insert_pos(rid)
		-- Return the index to insert rid, to keep inbound_requests sorted by rid.
		for idx, req in ipairs(session.inbound_requests) do
			if req.rid ~= nil then
				if req.rid >= rid then
					return idx
				end
			end
		end
		return #session.inbound_requests + 1;
	end

	-- Add the request to the request queue.
	local idx = find_insert_pos(request.rid);
	t_insert(session.inbound_requests, idx, request);
	log("debug", "inbound now has %i requests", #session.inbound_requests);

	-- Check for completed inbound requests, starting at the beginning of the queue.
	while not session.destroyed and #session.inbound_requests > 0 do
		local in_req = session.inbound_requests[1];
		if in_req.rid > session.previous_rid_processed+1 then
			log("debug", "rid %i is in the future; not handling it yet", in_req.rid);
			break;
		end

		-- This request is ready to be handled.  Remove it from the queue, and process it.
		log("debug", "handling inbound rid %i", in_req.rid);
		table.remove(session.inbound_requests, 1);

		if in_req.rid <= session.previous_rid_processed then
			-- This is an old RID.  It may be a rerequest (XEP-0124 sec14.3).  If we have
			-- a copy of the requested response, send it again.  Otherwise, terminate the
			-- session.
			log("debug", "rid %i is in the past", in_req.rid);
			local original_response = session.sent_responses.responses[in_req.rid];
			if original_response == nil then
				-- The client requested a RID that we no longer have a copy of.
				terminateWithError(in_req, session, "item-not-found");
				return true;
			end

			in_req:send(original_response);
		else
			process_request(in_req, session);
		end
		log("debug", "continue");
	end

	if session.destroyed then
		return true;
	end

	-- Purge old response history.
	while #session.sent_responses.rids > 0 do
		local oldest_stored_response_rid = session.sent_responses.rids[1];
		if oldest_stored_response_rid + response_history_size > session.previous_rid_processed then
			break
		end
		log("debug", "Purging response for rid %i", oldest_stored_response_rid);

		session.sent_responses.responses[oldest_stored_response_rid] = nil;
		table.remove(session.sent_responses.rids, 1);
	end

	return true;
end

-- All stanzas from a request have been received, and this request's
-- RID is next in line.
process_request = function(request, session)
	log("debug", "handle rid %i (next rid is %i)", tostring(request.rid), tostring(session.previous_rid_processed));
	local stanzas = request.stanzas;
	request.stanzas = {};
	session.previous_rid_processed = request.rid;
	for idx, stanza in ipairs(stanzas) do
		log("debug", "processing " .. tostring(idx) .. "...");
		core_process_stanza(session, stanza);
	end

	session.previous_rid_processed = request.rid
	table.insert(session.outbound_requests, request);

               -- Session was marked as inactive, since we have
               -- a request open now, unmark it
               if inactive_sessions[session] then
                       inactive_sessions[session] = nil;
               end

		local r = session.outbound_requests;
		log("debug", "Session %s has %d out of %d requests open", request.sid, #r, session.bosh_hold);
		log("debug", "and there are %d things in the send_buffer", #session.send_buffer);
		if session.notopen then
			log("debug", "Session isn't open; sending features");
			local features = st.stanza("stream:features");
			hosts[session.host].events.fire_event("stream-features", { origin = session, features = features });
			fire_event("stream-features", session, features);
			session.send(features);
			session.notopen = nil;
		elseif #session.send_buffer > 0 then
			log("debug", "Session has data in the send buffer, will send now..");
			local resp = t_concat(session.send_buffer);
			session.send_buffer = {};
			session.send(resp);
		elseif #r > session.bosh_hold then
			-- We are holding too many requests; release the oldest.
			log("debug", "We are holding too many requests, sending an empty response");
			session.send("");
		else
			-- We're keeping this request open, to respond later
			log("debug", "Have nothing to say, so leaving request unanswered for now");
			if session.bosh_wait then
				request.reply_before = os_time() + session.bosh_wait;
				waiting_requests[request] = true;
			end
		end
		
		-- Check if this request terminated the session.
		if session.bosh_terminate then
			log("debug", "Closing session with %d requests open", #session.outbound_requests);
			session:close();
			return;
		end
end


local function bosh_reset_stream(session) session.notopen = true; end

local stream_xmlns_attr = { xmlns = "urn:ietf:params:xml:ns:xmpp-streams" };

local function bosh_close_stream(session, reason)
	(session.log or log)("info", "BOSH client disconnected");
	
	local close_reply = st.stanza("body", { xmlns = xmlns_bosh, type = "terminate",
		["xmlns:streams"] = xmlns_streams });
	

	if reason then
		close_reply.attr.condition = "remote-stream-error";
		if type(reason) == "string" then -- assume stream error
			close_reply:tag("stream:error")
				:tag(reason, {xmlns = xmlns_xmpp_streams});
		elseif type(reason) == "table" then
			if reason.condition then
				close_reply:tag("stream:error")
					:tag(reason.condition, stream_xmlns_attr):up();
				if reason.text then
					close_reply:tag("text", stream_xmlns_attr):text(reason.text):up();
				end
				if reason.extra then
					close_reply:add_child(reason.extra);
				end
			elseif reason.name then -- a stanza
				close_reply = reason;
			end
		end
		log("info", "Disconnecting client, <stream:error> is: %s", tostring(close_reply));
	end

	local session_close_response = { headers = default_headers, body = tostring(close_reply) };

	-- Flush waiting outbound requests.  Note that send() will remove items from
	-- outbound_requests while we're iterating on it, so we can't use ipairs here.
	while #session.outbound_requests > 0 do
		local held_request = session.outbound_requests[1];
		held_request:send(session_close_response);
		held_request:destroy();
	end

	-- If any requests are in the inbound queue, close them without responding.
	for _, held_request in ipairs(session.inbound_requests) do
		held_request:destroy();
	end
	sessions[session.sid]  = nil;
	sm_destroy_session(session);
end

create_session = function(request)
	-- New session request
	local attr = request.attr;
	local sid = attr.sid
	local rid = tonumber(attr.rid);

	-- TODO: Sanity checks here (rid, to, known host, etc.)
	if not hosts[attr.to] then
		-- Unknown host
		log("debug", "BOSH client tried to connect to unknown host: %s", tostring(attr.to));
		local close_reply = st.stanza("body", { xmlns = xmlns_bosh, type = "terminate",
			["xmlns:streams"] = xmlns_streams, condition = "host-unknown" });
		request:send(tostring(close_reply));
		return;
	end

	-- New session
	sid = new_uuid();
	if module:get_option("bosh_debug") and attr.setsid then
		-- For testing only, allow selecting the SID.
		sid = attr.setsid;
	end
	local session = {
		type = "c2s_unauthed", conn = {}, sid = sid, host = attr.to,
		bosh_version = attr.ver, bosh_wait = attr.wait, streamid = sid,
		bosh_hold = BOSH_DEFAULT_HOLD,
		bosh_requests = BOSH_DEFAULT_REQUESTS,
		bosh_max_inactive = BOSH_DEFAULT_INACTIVITY,
		inbound_requests = {},
		outbound_requests = {},
		sent_responses = {
		    responses = {},
		    rids = {},
		},
		send_buffer = {}, reset_stream = bosh_reset_stream,
		close = bosh_close_stream, dispatch_stanza = core_process_stanza,
		log = logger.init("bosh"..sid),	secure = consider_bosh_secure or request.secure,
		ip = get_ip_from_request(request),
		previous_rid_processed = tonumber(rid),
	};
	if attr.hold ~= nil then
		local hold = tonumber(attr.hold);
		if hold < session.bosh_hold then
			log("debug", "Decreased hold from %i to %i at client request", session.bosh_hold, hold);
			session.bosh_hold = hold;
		end
	end

	-- Ensure that requests is always greater than hold.
	session.bosh_requests = math.max(session.bosh_hold+1, session.bosh_requests);

	sessions[sid] = session;

	session.log("debug", "BOSH session created for request from %s", session.ip);
	log("info", "New BOSH session, assigned it sid '%s'", sid);
	local r, send_buffer = session.outbound_requests, session.send_buffer;
	local response = { headers = default_headers }
	function session.send(s)
		-- We need to ensure that outgoing stanzas have the jabber:client xmlns
		if s.attr and not s.attr.xmlns then
			s = st.clone(s);
			s.attr.xmlns = "jabber:client";
		end
		--log("debug", "Sending BOSH data: %s", tostring(s));

		if #session.send_buffer > 0 or #r == 0 then
			if s == "" then
				return true;
			end
			log("debug", "Saved to send buffer because there are no open requests");
			-- Hmm, no requests are open :(
			t_insert(session.send_buffer, tostring(s));
			log("debug", "There are now %d things in the send_buffer", #session.send_buffer);
		else
			local oldest_request = table.remove(r, 1);
			waiting_requests[oldest_request] = nil;

			log("debug", "We have an open request, so sending on that");
			response.body = t_concat({
				"<body xmlns='http://jabber.org/protocol/httpbind' ",
				session.bosh_terminate and "type='terminate' " or "",
				"sid='", sid, "' xmlns:stream = 'http://etherx.jabber.org/streams'>",
				tostring(s),
				"</body>"
			});
			oldest_request:send(response);
			session.sent_responses.responses[oldest_request.rid] = response;
			t_insert(session.sent_responses.rids, oldest_request.rid);
			--log("debug", "Sent");
		end
		return true;
	end

	-- Send creation response

	local features = st.stanza("stream:features");
	hosts[session.host].events.fire_event("stream-features", { origin = session, features = features });
	fire_event("stream-features", session, features);
	--xmpp:version='1.0' xmlns:xmpp='urn:xmpp:xbosh'
	local response = st.stanza("body", { xmlns = xmlns_bosh,
		wait = attr.wait,
		inactivity = tostring(BOSH_DEFAULT_INACTIVITY),
		polling = tostring(BOSH_DEFAULT_POLLING),
		requests = tostring(session.bosh_requests),
		hold = tostring(session.bosh_hold),
		sid = sid, authid = sid,
		ver  = '1.6', from = session.host,
		secure = 'true', ["xmpp:version"] = "1.0",
		["xmlns:xmpp"] = "urn:xmpp:xbosh",
		["xmlns:stream"] = "http://etherx.jabber.org/streams"
	}):add_child(features);
	request:send{ headers = default_headers, body = tostring(response) };
	return;
end

function stream_callbacks.streamopened(request, attr)
	log("debug", "BOSH body open (sid: %s)", attr.sid);
	request.rid = tonumber(attr.rid);
	request.sid = attr.sid;
	request.attr = attr;

	request.notopen = nil; -- Signals that we accept this opening tag
end

function stream_callbacks.streamclosed(request, attr)
	log("debug", "BOSH request closed");
	request.closed = true;
end

function stream_callbacks.handlestanza(request, stanza)
	log("debug", "BOSH stanza received: %s\n", stanza:top_tag());
	local session = sessions[request.sid];
	if session then
		if stanza.attr.xmlns == xmlns_bosh then
			stanza.attr.xmlns = nil;
		end
		t_insert(request.stanzas, stanza);
	end
end

function stream_callbacks.error(request, error)
	log("debug", "Error parsing BOSH request payload; %s", error);
	if not request.sid then
		request:send({ headers = default_headers, status = "400 Bad Request" });
		return;
	end
	
	local session = sessions[request.sid];
	if error == "stream-error" then -- Remote stream error, we close normally
		session:close();
	else
		session:close({ condition = "bad-format", text = "Error processing stream" });
	end
end

local dead_sessions = {};
function on_timer()
	-- log("debug", "Checking for requests soon to timeout...");
	-- Identify requests timing out within the next few seconds
	local now = os_time() + 3;
	for request in pairs(waiting_requests) do
		if request.reply_before <= now then
			log("debug", "%s was soon to timeout, sending empty response", request.id);
			-- Send empty response to let the
			-- client know we're still here
			if request.conn then
				sessions[request.sid].send("");
			end
		end
	end
	
	now = now - 3;
	local n_dead_sessions = 0;
	for session, inactive_since in pairs(inactive_sessions) do
		if session.bosh_max_inactive then
			if now - inactive_since > session.bosh_max_inactive then
				(session.log or log)("debug", "BOSH client inactive too long, destroying session at %d", now);
				sessions[session.sid]  = nil;
				inactive_sessions[session] = nil;
				n_dead_sessions = n_dead_sessions + 1;
				dead_sessions[n_dead_sessions] = session;
			end
		else
			inactive_sessions[session] = nil;
		end
	end

	for i=1,n_dead_sessions do
		local session = dead_sessions[i];
		dead_sessions[i] = nil;
		sm_destroy_session(session, "BOSH client silent for over "..session.bosh_max_inactive.." seconds");
	end
	return 1;
end


local function setup()
	local ports = module:get_option("bosh_ports") or { 5280 };
	httpserver.new_from_config(ports, handle_request, { base = "http-bind" });
	timer.add_task(1, on_timer);
end
if prosody.start_time then -- already started
	setup();
else
	prosody.events.add_handler("server-started", setup);
end
