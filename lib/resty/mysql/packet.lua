-- Copyright (C) 2017 Libo Huang (huangnauh), UPYUN Inc.
local bit           = require "bit"
local const         = require "resty.mysql.const"

local sub           = string.sub
local strlen        = string.len
local strbyte       = string.byte
local strchar       = string.char
local strfind       = string.find
local strsub        = string.sub
local format        = string.format
local strrep        = string.rep
local tcp           = ngx.socket.tcp
local null          = ngx.null
local ERR           = ngx.ERR
local WARN          = ngx.WARN
local INFO          = ngx.INFO
local log           = ngx.log
local band          = bit.band
local bxor          = bit.bxor
local bor           = bit.bor
local lshift        = bit.lshift
local rshift        = bit.rshift
local tohex         = bit.tohex
local sha1          = ngx.sha1_bin
local concat        = table.concat
local unpack        = unpack
local setmetatable  = setmetatable
local error         = error
local tonumber      = tonumber
local tostring      = tostring

if not ngx.config
   or not ngx.config.ngx_lua_version
   or ngx.config.ngx_lua_version < 9011
then
    error("ngx_lua 0.9.11+ required")
end

local STATE_CONNECTED = 1
local STATE_COMMAND_SENT = 2

local ok, new_tab = pcall(require, "table.new")
if not ok then
    new_tab = function (narr, nrec) return {} end
end

local _M = { _VERSION = '0.01' }

local mt = { __index = _M }

-- mysql field value type converters
local converters = new_tab(0, 9)

for i = 0x01, 0x05 do
    -- tiny, short, long, float, double
    converters[i] = tonumber
end
converters[0x00] = tonumber  -- decimal
-- converters[0x08] = tonumber  -- long long
converters[0x09] = tonumber  -- int24
converters[0x0d] = tonumber  -- year
converters[0xf6] = tonumber  -- newdecimal


local function _get_byte2(data, i)
    local a, b = strbyte(data, i, i + 1)
    return bor(a, lshift(b, 8)), i + 2
end


local function _get_byte3(data, i)
    local a, b, c = strbyte(data, i, i + 2)
    return bor(a, lshift(b, 8), lshift(c, 16)), i + 3
end


local function _get_byte4(data, i)
    local a, b, c, d = strbyte(data, i, i + 3)
    return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24)), i + 4
end


local function _get_byte8(data, i)
    local a, b, c, d, e, f, g, h = strbyte(data, i, i + 7)

    -- XXX workaround for the lack of 64-bit support in bitop:
    local lo = bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24))
    local hi = bor(e, lshift(f, 8), lshift(g, 16), lshift(h, 24))
    return lo + hi * 4294967296, i + 8

    -- return bor(a, lshift(b, 8), lshift(c, 16), lshift(d, 24), lshift(e, 32),
               -- lshift(f, 40), lshift(g, 48), lshift(h, 56)), i + 8
end


local function _set_byte2(n)
    return strchar(band(n, 0xff), band(rshift(n, 8), 0xff))
end


local function _set_byte3(n)
    return strchar(band(n, 0xff),
                   band(rshift(n, 8), 0xff),
                   band(rshift(n, 16), 0xff))
end


local function _set_byte4(n)
    return strchar(band(n, 0xff),
                   band(rshift(n, 8), 0xff),
                   band(rshift(n, 16), 0xff),
                   band(rshift(n, 24), 0xff))
end


local function _from_cstring(data, i)
    local last = strfind(data, "\0", i, true)
    if not last then
        return nil, nil
    end

    return sub(data, i, last-1), last + 1
end


local function _to_cstring(data)
    return data .. "\0"
end


local function _to_binary_coded_string(data)
    return strchar(#data) .. data
end


local function _dump(data)
    local len = #data
    local bytes = new_tab(len, 0)
    for i = 1, len do
        bytes[i] = format("%x", strbyte(data, i))
    end
    return concat(bytes, " ")
end


local function _dumphex(data)
    local len = #data
    local bytes = new_tab(len, 0)
    for i = 1, len do
        bytes[i] = tohex(strbyte(data, i), 2)
    end
    return concat(bytes, " ")
end


local function _compute_token(password, scramble)
    if password == "" then
        return ""
    end

    local stage1 = sha1(password)
    local stage2 = sha1(stage1)
    local stage3 = sha1(scramble .. stage2)
    local n = #stage1
    local bytes = new_tab(n, 0)
    for i = 1, n do
         bytes[i] = strchar(bxor(strbyte(stage3, i), strbyte(stage1, i)))
    end

    return concat(bytes)
end


local function _send_packet(self, req, size)
    local sock = self.sock

    self.packet_no = self.packet_no + 1

    -- print("packet no: ", self.packet_no)

    local packet = _set_byte3(size) .. strchar(band(self.packet_no, 255)) .. req

--     print("sending packet: ", _dump(packet))
--
--     print("sending packet... of size " .. #packet)

    return sock:send(packet)
end
_M.send_packet = _send_packet


local function _recv_packet(self)
    local sock = self.sock

    local data, err = sock:receive(4) -- packet header
    if not data then
        return nil, "failed to receive packet header: " .. err
    end

--    print("packet header: ", _dump(data))

    local len, pos = _get_byte3(data, 1)

--    print("packet length: ", len)

    if len == 0 then
        return nil, "empty packet"
    end

    if len > self.max_packet_size then
        return nil, "packet size too big: " .. len
    end

    local num = strbyte(data, pos)

    --print("recv packet: packet no: ", num)

    self.packet_no = num

    data, err = sock:receive(len)

    --print("receive returned")

    if not data then
        return nil, "failed to read packet content: " .. err
    end

--    print("packet content: ", _dump(data))
--    print("packet content (ascii): ", data)
    return data
end
_M.recv_packet = _recv_packet


local function _type(data)
    local field_count = strbyte(data, 1)
    local typ
    if field_count == const.OK_HEADER then
        typ = "OK"
    elseif field_count == const.ERR_HEADER then
        typ = "ERR"
    elseif field_count == const.EOF_HEADER then
        typ = "EOF"
    elseif field_count <= const.DATA_HEADER_UPPER then
        typ = "DATA"
    end
    return tostring(typ)
end
_M.type = _type


function _M.cmd(data)
    return strbyte(data, 1)
end


local function _to_length_coded_bin(num)
    if num <= 250 then
        return strchar(num)
    end

    if num <= 0xffff then
        return strchar(252, band(num, 0xff), band(rshift(num, 8), 0xff))
    end

    if num <= 0xffffff then
        return strchar(253, band(num, 0xff), band(rshift(num, 8), 0xff),
            band(rshift(num, 16), 0xff))
    end

    if num <= 0xffffffffffffffff then
        return strchar(254, band(num, 0xff), band(rshift(num, 8), 0xff),
            band(rshift(num, 16), 0xff), band(rshift(num, 24), 0xff),
            band(rshift(num, 32), 0xff), band(rshift(num, 48), 0xff),
            band(rshift(num, 56), 0xff))
    end
    return ""
end
_M.to_length_coded_bin = _to_length_coded_bin


local function _to_length_coded_str(str)
    local len = #str
    return _to_length_coded_bin(len) .. str
end


local function _from_length_coded_bin(data, pos)
    local first = strbyte(data, pos)

    --print("LCB: first: ", first)

    if not first then
        return nil, pos
    end

    if first >= 0 and first <= 250 then
        return first, pos + 1
    end

    if first == 251 then
        return null, pos + 1
    end

    if first == 252 then
        pos = pos + 1
        return _get_byte2(data, pos)
    end

    if first == 253 then
        pos = pos + 1
        return _get_byte3(data, pos)
    end

    if first == 254 then
        pos = pos + 1
        return _get_byte8(data, pos)
    end

    return nil, pos + 1
end


local function _from_length_coded_str(data, pos)
    local len
    len, pos = _from_length_coded_bin(data, pos)
    if not len or len == null then
        return null, pos
    end

    return sub(data, pos, pos + len - 1), pos + len
end


function _M.parse_handshake_packet(self, packet)
    local capability, pos = _get_byte4(packet, 1)
    self.capability = capability
--    print("capability (ascii): ", capability)
--    print("pos:", pos)
    -- skip max packet size
    pos = pos + 4
    -- skip charset
    pos = pos + 1
    -- skip reserved 23[00]
	pos = pos + 23

    local user
    user, pos = _from_cstring(packet, pos)
    if not user then
        return "empty user"
    end

    log(INFO, "connect with user: ", user)
    if self.user ~= user then
        return "invalid user"
    end

    local auth_len = strbyte(strsub(packet, pos, pos + 1))
    if auth_len == 0 then
       return "empty auth"
    end
    pos = pos + 1

    local auth = strsub(packet, pos, pos+auth_len-1)
    pos = pos + auth_len
    self.auth = auth

    local token = _compute_token(self.password, self.salt)
--    print("auth_len:", _dump(auth), ",token:", _dump(token))
    if token ~= auth then
        return "invalid auth"
    end

    if bor(self.capability, const.CAPABILITY_MAP.CLIENT_CONNECT_WITH_DB) == 0 then
        return "empty db"
    end

    local db, pos = _from_cstring(packet, pos)
--    print("db:", db, ", len:", #db)
    if db == nil or strlen(db) == 0 then
        return "empty db"
    end
    self.db = db
end


local function send_ok_packet(self, res)
    local res = res or {}
    local insert_id = res.insert_id or 0
    local affected_rows = res.affected_rows or 0
    local data = strchar(const.OK_HEADER)
            .. _to_length_coded_bin(affected_rows)
            .. _to_length_coded_bin(insert_id)
    if band(self.capability, const.CAPABILITY_MAP.CLIENT_PROTOCOL_41) > 0 then
        data = data .. _set_byte2(self.status) .. strrep("\0", 2)
    end
    return _send_packet(self, data, #data)
end
_M.send_ok_packet = send_ok_packet


local function _parse_ok_packet(packet)
    local res = new_tab(0, 5)
    local pos

    res.affected_rows, pos = _from_length_coded_bin(packet, 2)

--    print("affected rows: ", res.affected_rows, ", pos:", pos)

    res.insert_id, pos = _from_length_coded_bin(packet, pos)

--    print("insert id: ", res.insert_id, ", pos:", pos)

    res.server_status, pos = _get_byte2(packet, pos)

--    print("server status: ", res.server_status, ", pos:", pos)

    res.warning_count, pos = _get_byte2(packet, pos)

--    print("warning count: ", res.warning_count, ", pos: ", pos)

    local message = _from_length_coded_str(packet, pos)
    if message and message ~= null then
        res.message = message
    end

--    print("message: ", res.message, ", pos:", pos)

    return res
end


local function _dump_eof_packet(self)
    local data = strchar(const.EOF_HEADER)
    if band(self.capability, const.CAPABILITY_MAP.CLIENT_PROTOCOL_41) > 0 then
        data = data .. strrep("\0", 2) .. _set_byte2(self.status)
    end
    return data
end


local function _send_eof_packet(self)
    local data = _dump_eof_packet(self)
    return _send_packet(self, data, #data)
end
_M.send_eof_packet = _send_eof_packet


local function _parse_eof_packet(packet)
    local pos = 2

    local warning_count, pos = _get_byte2(packet, pos)
    local status_flags = _get_byte2(packet, pos)

    return warning_count, status_flags
end


function _M.send_error_packet(self, sql_err)
    local data = strchar(const.ERR_HEADER)
            .. _set_byte2(sql_err.errno)
    if band(self.capability, const.CAPABILITY_MAP.CLIENT_PROTOCOL_41) > 0 then
        data = data .. "#" .. sql_err.sqlstate
    end
    data = data .. sql_err.message
    return _send_packet(self, data, #data)
end


local function _parse_err_packet(packet)
    local errno, pos = _get_byte2(packet, 2)
    local marker = sub(packet, pos, pos)
    local sqlstate
    if marker == '#' then
        -- with sqlstate
        pos = pos + 1
        sqlstate = sub(packet, pos, pos + 5 - 1)
        pos = pos + 5
    end

    local message = sub(packet, pos)
    return errno, message, sqlstate
end


local function _parse_result_set_header_packet(packet)
    local field_count, pos = _from_length_coded_bin(packet, 1)

    local extra
    extra = _from_length_coded_bin(packet, pos)

    return field_count, extra
end


local function _parse_field_packet(data)
    local col = {}
--    local catalog, db, table, orig_table, orig_name, charsetnr, length
    local pos
    col.catalog, pos = _from_length_coded_str(data, 1)

--    print("catalog: ", col.catalog, ", pos:", pos)

    col.db, pos = _from_length_coded_str(data, pos)
    col.table, pos = _from_length_coded_str(data, pos)
    col.orig_table, pos = _from_length_coded_str(data, pos)
    col.name, pos = _from_length_coded_str(data, pos)

    col.orig_name, pos = _from_length_coded_str(data, pos)

    pos = pos + 1 -- ignore the filler 0x0c

    col.charsetnr, pos = _get_byte2(data, pos)

    col.length, pos = _get_byte4(data, pos)

    col.type = strbyte(data, pos)

    pos = pos + 1

    col.flags, pos = _get_byte2(data, pos)

    col.decimals = strbyte(data, pos)
    pos = pos + 1

    local default = sub(data, pos + 2)
    if default and default ~= "" then
        col.default = default
    end

    return col
end


local function _parse_row_data_packet(data, cols, compact)
    local pos = 1
    local ncols = #cols
    local row
    if compact then
        row = new_tab(ncols, 0)
    else
        row = new_tab(0, ncols)
    end
    for i = 1, ncols do
        local value
        value, pos = _from_length_coded_str(data, pos)
        local col = cols[i]
        local typ = col.type
        local name = col.name

        --print("row field value: ", value, ", type: ", typ)

        if value ~= null then
            local conv = converters[typ]
            if conv then
                value = conv(value)
            end
        end

        if compact then
            row[i] = value

        else
            row[name] = value
        end
    end

    return row
end


local function _recv_field_packet(self, raw)
    local packet, err = _recv_packet(self)
    if not packet then
        return nil, err
    end

    local typ = _type(packet)
    if typ == "ERR" then
        local errno, msg, sqlstate = _parse_err_packet(packet)
        return nil, msg, errno, sqlstate
    end

    if typ ~= 'DATA' then
        return nil, "bad field packet type: " .. typ
    end

    -- typ == 'DATA'
    if raw then
        return packet
    end

    return _parse_field_packet(packet)
end

function _M.set_timeout(self, timeout)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    return sock:settimeout(timeout)
end


function _M.connect(self, opts)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    local max_packet_size = opts.max_packet_size
    if not max_packet_size then
        max_packet_size = const.MAX_PACKET_SIZE
    end
    self.max_packet_size = max_packet_size

    local ok, err

    self.compact = opts.compact_arrays

    local database = opts.database or ""
    local user = opts.user or ""

    local charset = const.CHARSET_MAP[opts.charset or "_default"]
    if not charset then
        return nil, "charset '" .. opts.charset .. "' is not supported"
    end

    local pool = opts.pool

    local host = opts.host
    if host then
        local port = opts.port or 3306
        if not pool then
            pool = user .. ":" .. database .. ":" .. host .. ":" .. port
        end

        ok, err = sock:connect(host, port, { pool = pool })

    else
        local path = opts.path
        if not path then
            return nil, 'neither "host" nor "path" options are specified'
        end

        if not pool then
            pool = user .. ":" .. database .. ":" .. path
        end

        ok, err = sock:connect("unix:" .. path, { pool = pool })
    end

    if not ok then
        return nil, 'failed to connect: ' .. err
    end

    local reused = sock:getreusedtimes()
--    print("reused:", reused)
    if reused and reused > 0 then
        self.state = STATE_CONNECTED
        return 1
    end

    local packet, err = _recv_packet(self)
    if not packet then
        return nil, err
    end

    local typ = _type(packet)
    if typ == "ERR" then
        local errno, msg, sqlstate = _parse_err_packet(packet)
        return nil, msg, errno, sqlstate
    end

    self.protocol_ver = strbyte(packet)

    --print("protocol version: ", self.protocol_ver)

    local server_ver, pos = _from_cstring(packet, 2)
    if not server_ver then
        return nil, "bad handshake initialization packet: bad server version"
    end

--    print("server version: ", server_ver, ", len:", #server_ver)

    self._server_ver = server_ver

    local thread_id, pos = _get_byte4(packet, pos)

    --print("thread id: ", thread_id)

    local scramble = sub(packet, pos, pos + 8 - 1)
    if not scramble then
        return nil, "1st part of scramble not found"
    end

    pos = pos + 9 -- skip filler

    -- two lower bytes
    local capabilities  -- server capabilities
    capabilities, pos = _get_byte2(packet, pos)

    -- print(format("server capabilities: %#x", capabilities))

    self._server_lang = strbyte(packet, pos)
    pos = pos + 1

    --print("server lang: ", self._server_lang)

    self._server_status, pos = _get_byte2(packet, pos)

    --print("server status: ", self._server_status)

    local more_capabilities
    more_capabilities, pos = _get_byte2(packet, pos)

    capabilities = bor(capabilities, lshift(more_capabilities, 16))

    --print("server capabilities: ", capabilities)

    -- local len = strbyte(packet, pos)
    local len = 21 - 8 - 1

    --print("scramble len: ", len)

    pos = pos + 1 + 10

    local scramble_part2 = sub(packet, pos, pos + len - 1)
    if not scramble_part2 then
        return nil, "2nd part of scramble not found"
    end

    scramble = scramble .. scramble_part2
    --print("scramble: ", _dump(scramble))

    local client_flags = 0x3f7cf;

    local ssl_verify = opts.ssl_verify
    local use_ssl = opts.ssl or ssl_verify

    local ssl_cap = const.CAPABILITY_MAP.CLIENT_SSL
    if use_ssl then
        if band(capabilities, ssl_cap) == 0 then
            return nil, "ssl disabled on server"
        end

        -- send a SSL Request Packet
        local req = _set_byte4(bor(client_flags, ssl_cap))
                    .. _set_byte4(self.max_packet_size)
                    .. strchar(charset)
                    .. strrep("\0", 23)

        local packet_len = 4 + 4 + 1 + 23
        local bytes, err = _send_packet(self, req, packet_len)
        if not bytes then
            return nil, "failed to send client authentication packet: " .. err
        end

        local ok, err = sock:sslhandshake(false, nil, ssl_verify)
        if not ok then
            return nil, "failed to do ssl handshake: " .. (err or "")
        end
    end

    local password = opts.password or ""

    local token = _compute_token(password, scramble)

--    print("token: ", _dump(token))

    local req = _set_byte4(client_flags)
                .. _set_byte4(self.max_packet_size)
                .. strchar(charset)
                .. strrep("\0", 23)
                .. _to_cstring(user)
                .. _to_binary_coded_string(token)
                .. _to_cstring(database)

    local packet_len = 4 + 4 + 1 + 23 + #user + 1
        + #token + 1 + #database + 1

--     print("packet content length: ", packet_len)
--     print("packet content: ", _dump(req))

    local bytes, err = _send_packet(self, req, packet_len)
    if not bytes then
        return nil, "failed to send client authentication packet: " .. err
    end

--    print("packet sent ", bytes, " bytes")

    local packet, err = _recv_packet(self)
    if not packet then
        return nil, "failed to receive the result packet: " .. err
    end

    local typ = _type(packet)

    if typ == 'ERR' then
        local errno, msg, sqlstate = _parse_err_packet(packet)
        return nil, msg, errno, sqlstate
    end

    if typ == 'EOF' then
        return nil, "old pre-4.1 authentication protocol not supported"
    end

    if typ ~= 'OK' then
        return nil, "bad packet type: " .. typ
    end

    self.state = STATE_CONNECTED

    return 1
end


function _M.set_keepalive(self, ...)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    if self.state ~= STATE_CONNECTED then
        return nil, "cannot be reused in the current connection state: "
                    .. (self.state or "nil")
    end

    self.state = nil
    return sock:setkeepalive(...)
end


function _M.get_reused_times(self)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    return sock:getreusedtimes()
end


function _M.close(self)
    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    self.state = nil

    local bytes, err = _send_packet(self, strchar(const.COM_MAP.COM_QUIT), 1)
    if not bytes then
        return nil, err
    end

    return sock:close()
end


function _M.server_ver(self)
    return self._server_ver
end


local function send_data(self, data)
    if self.state ~= STATE_CONNECTED then
        return nil, "cannot send data in the current context: "
                    .. (self.state or "nil")
    end

    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    self.packet_no = -1

    local bytes, err = _send_packet(self, data, #data)
    if not bytes then
        return nil, err
    end

    self.state = STATE_COMMAND_SENT

    --print("packet sent ", bytes, " bytes")

    return bytes
end
_M.send_data = send_data


local function send_query(self, query)
    if self.state ~= STATE_CONNECTED then
        return nil, "cannot send query in the current context: "
                    .. (self.state or "nil")
    end

    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    self.packet_no = -1

    local cmd_packet = strchar(const.COM_MAP.COM_QUERY) .. query
    local packet_len = 1 + #query

    local bytes, err = _send_packet(self, cmd_packet, packet_len)
    if not bytes then
        return nil, err
    end

    self.state = STATE_COMMAND_SENT

    --print("packet sent ", bytes, " bytes")

    return bytes
end
_M.send_query = send_query


local function send_result_rows(self, res)
    local ncols = #res.cols
    local nrows = #res
--    local bytes = new_tab(n, 0)
    local total = 0

    local data = _to_length_coded_bin(ncols)
    local len = #data
    local _, err = _send_packet(self, data, len)
    if err then
        return nil, err
    end

    total = total + len

    -- send raw field
    for i = 1, ncols do
        data = res.cols[i]
        len = #data
        _, err = _send_packet(self, data, len)
        if err then
            return nil, err
        end
        total = total + len
    end

    len, err = _send_eof_packet(self)
    if err then
        return nil, err
    end
    total = total + len

    -- send raw data
    for i = 1, nrows do
        data = res[i]
        len = #data
        _, err = _send_packet(self, data, len)
        if err then
            return nil, err
        end
        total = total + len
    end

    len, err = _send_eof_packet(self)
    if err then
        return err
    end
    total = total + len
    return total, nil
end


function _M.send_result(self, res)
    if res[1] then
        return send_result_rows(self, res)
    else
        return send_ok_packet(self, res)
    end
end


local function read_result(self, raw, est_nrows)
    if self.state ~= STATE_COMMAND_SENT then
        return nil, "cannot read result in the current context: "
                    .. (self.state or "nil")
    end

    local sock = self.sock
    if not sock then
        return nil, "not initialized"
    end

    local packet, err = _recv_packet(self)
    if not packet then
        return nil, err
    end

    local typ = _type(packet)

    if typ == "ERR" then
        self.state = STATE_CONNECTED

        local errno, msg, sqlstate = _parse_err_packet(packet)
        return nil, msg, errno, sqlstate
    end

    if typ == 'OK' then
        local res = _parse_ok_packet(packet)
        if res and band(res.server_status, const.SERVER_STATUS_MAP.SERVER_MORE_RESULTS_EXISTS) ~= 0 then
            return res, "again"
        end

        self.state = STATE_CONNECTED
        return res
    end

    if typ ~= 'DATA' then
        self.state = STATE_CONNECTED

        return nil, "packet type " .. typ .. " not supported"
    end

    -- typ == 'DATA'

--    print("read the result set header packet")

    local field_count, extra = _parse_result_set_header_packet(packet)

--    print("field count: ", field_count)

    local cols = new_tab(field_count, 0)
    for i = 1, field_count do
        local col, err, errno, sqlstate = _recv_field_packet(self, raw)
        if not col then
            return nil, err, errno, sqlstate
        end

        cols[i] = col
    end

    local packet, err = _recv_packet(self)
    if not packet then
        return nil, err
    end

    local typ = _type(packet)
    if typ ~= 'EOF' then
        return nil, "unexpected packet type " .. typ .. " while eof packet is "
            .. "expected"
    end

    -- typ == 'EOF'

    local compact = self.compact

    local rows = new_tab(est_nrows or 4, 1)
    if raw then
        rows.cols = cols
    end

    local i = 0
    while true do
--        print("reading a row")

        packet, err = _recv_packet(self)
        if not packet then
            return nil, err
        end

        typ = _type(packet)
        if typ == 'EOF' then
            local warning_count, status_flags = _parse_eof_packet(packet)

--            print("status flags: ", status_flags)

            if band(status_flags, const.SERVER_STATUS_MAP.SERVER_MORE_RESULTS_EXISTS) ~= 0 then
                return rows, "again"
            end

            break
        end

        -- if typ ~= 'DATA' then
            -- return nil, 'bad row packet type: ' .. typ
        -- end

        -- typ == 'DATA'

        i = i + 1
        if raw then
            rows[i] = packet
        else
            local row = _parse_row_data_packet(packet, cols, compact)
            rows[i] = row
        end
    end

    self.state = STATE_CONNECTED

    return rows
end
_M.read_result = read_result


function _M.query(self, query, est_nrows)
    local bytes, err = send_query(self, query)
    if not bytes then
        return nil, "failed to send query: " .. err
    end

    return read_result(self, est_nrows)
end


function _M.set_compact_arrays(self, value)
    self.compact = value
end


function _M.init_handshake(self)
    local data = strchar(const.MIN_PROTOCOL_VERISON)
            .. _to_cstring(const.SERVER_VERISON)
            .. _set_byte4(self.conn_id)
            .. _to_cstring(strsub(self.salt, 1, 8))
            .. _set_byte2(const.DEFAULT_CAPABILITY)
            .. strchar(const.DEFAULT_COLLATION_ID)
            .. _set_byte2(self.status)
            .. strchar(band(rshift(const.DEFAULT_CAPABILITY, 16), 0xff))
            .. strchar(band(rshift(const.DEFAULT_CAPABILITY, 24), 0xff))
            .. strchar(0x15)
            .. strrep("\0", 10)
            .. _to_cstring(strsub(self.salt, 9, -1))

    local len = 1 + strlen(const.SERVER_VERISON) + 1 + 4 + 9 + 1 + 2 + 1 + 2 + 3 + 10
                + strlen(strsub(self.salt, 9, -1))
--    print("##############", len, #data)
    return data, #data
end


function _M.new(self, conn)
    if not conn then
        local sock, err = tcp()
        if not sock then
            return nil, err
        end
        conn = { sock = sock, packet_no = -1 }
    end
    return setmetatable(conn, mt)
end


return _M
