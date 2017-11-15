-- Copyright (C) 2017 Libo Huang (huangnauh), UPYUN Inc.
local checkups      = require "resty.checkups.api"
local const         = require "resty.mysql.const"
local packet        = require "resty.mysql.packet"

local type          = type
local rawget        = rawget
local ipairs        = ipairs
local setmetatable  = setmetatable
local tostring      = tostring
local strbyte       = string.byte
local strchar       = string.char
local strfind       = string.find
local format        = string.format
local strrep        = string.rep
local rand          = math.random
local req_sock      = ngx.req.socket
local null          = ngx.null
local ERR           = ngx.ERR
local WARN          = ngx.WARN
local INFO          = ngx.INFO
local log           = ngx.log
local spawn         = ngx.thread.spawn
local wait          = ngx.thread.wait
local slardar       = slardar

local _M = { _VERSION = '0.01' }

local mt = { __index = _M }

local conn_id = const.BASE_CONN_ID

local function rand_str(length)
    local s = ""
    for i=1, length do
        s = s .. strchar(rand(256)-1)
    end
    return s
end

function _M.new(self, config)
    local sock, err = req_sock(true)
    if not sock then
        log(ERR, "failed to get the request socket: ", err)
        return nil, err
    end

    conn_id = conn_id + 1
    local conn = {
        sock            = sock,
        conn_id         = conn_id,
        user            = config.user,
        password        = config.password,
        status          = config.status or const.SERVER_STATUS_MAP.SERVER_STATUS_AUTOCOMMIT,
        salt            = rand_str(20),
        packet_no       = -1,
        capability      = config.capability or 0,
        max_packet_size = config.max_packet_size or const.MAX_PACKET_SIZE,
    }

    local pkt = packet:new(conn)
    return setmetatable({pkt = pkt}, mt)
end


local function backend(self)
    local ups = slardar.mysql
    local db = packet:new()
    db:set_timeout(10000)

    local backend_connect = function(host, port)
        local ok, err, errno, sqlstate = db:connect{
            host = host,
            port = port,
            database = ups.name,
            user = ups.user,
            password = ups.pass,
            max_packet_size = 1024 * 1024 }

        if not ok and err then
            log(WARN, "failed to connect: ",
                err, ": ", errno, " ", sqlstate)
        end
        return ok, err
    end

    local ok, err = checkups.ready_ok("mysql", backend_connect)
    if not ok then
        return err
    end
    self.bkd = db
end


function _M.handshake(self)
    local data, len = self.pkt:init_handshake()
    local _, err = self.pkt:send_packet(data, len)
    if err then
        log(ERR, "failed to send initial handshake, err=",err)
        return err
    end

    local data, err = self.pkt:recv_packet()
    if err then
        log(ERR, "failed to read handshake response, err=",err)
        return err
    end

    err = self.pkt:parse_handshake_packet(data)
    if err then
        log(ERR, "failed to parse handshake packet, err=",err)
        self.pkt:send_error_packet({
            errno=const.ERROR.ER_HANDSHAKE_ERROR,
            message=const.DEFAULT_MYSQL_ERRMESSAGE,
            sqlstate=const.DEFAULT_MYSQL_STATE})
        return err
    end

    err = backend(self)
    if err then
        log(ERR, "failed to connect mysql, err=",err)
        self.pkt:send_error_packet({
            errno=const.ERROR.ER_ABORTING_CONNECTION,
            message=const.DEFAULT_MYSQL_ERRMESSAGE,
            sqlstate=const.DEFAULT_MYSQL_STATE})
        return err
    end

    local _, err = self.pkt:send_ok_packet()
    if err then
        log(ERR, "send ok handshake failed, err=",err)
        return err
    end
    return nil
end


local function query(self, data)
--    print("query bkd send_data")
    local _, err = self.bkd:send_data(data)
    if err then
        log(ERR, "bkd failed to send_packet, err=",err)
        return false, err
    end

--    print("query bkd read_result")
    local res, err, errno, sqlstate = self.bkd:read_result(true)
    if errno then
        self.pkt:send_error_packet({
            errno=errno,
            message=err,
            sqlstate=sqlstate})
        return true, nil
    elseif err then
        log(ERR, "bkd failed to send_packet, err=",err)
        self.pkt:send_error_packet({
            errno=const.ERROR.ER_ABORTING_CONNECTION,
            message=const.DEFAULT_MYSQL_ERRMESSAGE,
            sqlstate=const.DEFAULT_MYSQL_STATE})
        return false, err
    end

--    print("query pkt send_result")
    _, err = self.pkt:send_result(res)
    if err then
        return false, err
    else
        return true, nil
    end
end


local function quit(self, data)
    local _, err = self.bkd:set_keepalive(10000, 100)
    if err then
        log(WARN, "set_keepalive failed, err=",err)
    end
    return false, nil
end


local supported = {
    [const.COM_MAP.COM_QUERY]   = query,
    [const.COM_MAP.COM_QUIT]    = quit,
}


local function dispatch(self, data)
    local func = supported[packet.cmd(data)]
    if func then
        return func(self, data)
    else
        self.pkt:send_error_packet({
            errno=const.ERROR.ER_UNKNOWN_ERROR,
            message=const.DEFAULT_MYSQL_ERRMESSAGE,
            sqlstate=const.DEFAULT_MYSQL_STATE})
        return true, nil
    end
end


function _M.process(self)
    while true do
--        print("pkt recv_packet")
        local data, err = self.pkt:recv_packet()
        if err then
            log(ERR, "pkt failed to recv_packet, err=",err)
            break
        end

        if data and data ~= "" then
--            print("type:", data[1], data)
            local ok, err = dispatch(self, data)
--            print("ok:", ok, ", err:", err)
            if err or not ok then
                break
            end
        end
    end
end


return _M
