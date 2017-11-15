local proxy = require "resty.mysql.proxy"

local conn, err = proxy:new({user="runner", password="runner123456"})
if err then
    return
end

err = conn:handshake()
if err then
    return
end

conn:process()
