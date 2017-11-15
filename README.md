# work-in-progress

Name
====

lua-resty-mysql-toolset - Lua mysql client and server toolset based on openresty/lua-resty-mysql

Table of Contents
=================
* [Name](#name)
* [Status](#status)
* [Synopsis](#synopsis)

Status
======

This library is still in its early stages of development.


Synopsis
========

```
stream {
    server {
        -- mysql proxy listen on 1234
        -- user: runner
		-- password: runner123456
        listen 1234;
        content_by_lua_block {
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
        }
    }
}
```
