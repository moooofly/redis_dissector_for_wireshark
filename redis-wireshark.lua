-- Wireshark packet dissector for Redis
-- Protocol specification: http://redis.io/topics/protocol
-- Written by John Zwinck, 29 November 2011
-- Revised by moooofly, 14 November 2016

do -- scope
    local proto = Proto('redis', 'Redis Protocol')

    local f = proto.fields
    -- we could make more of these, e.g. to distinguish keys from values
    f.value   = ProtoField.string('redis.value',   'Value')

----

    mtypes = {
        ['+'] = 'Simple Strings',
        ['-'] = 'Errors',
        [':'] = 'Integers',
        ['$'] = 'Bulk Strings',
        ['*'] = 'Arrays',
    }

    local CRLF = 2 -- constant length of \r\n

    -- recursively parse and generate a tree of data from messages in a packet
    -- root: the tree root to populate under
    -- buffer: the entire packet buffer
    -- pktinfo:
    -- offset: the current offset in the buffer
    -- matches: a one-pass generator function which yields parsed lines from the packet
    -- returns: the new offset (i.e. the input offset plus the number of bytes consumed)
    local function recurse(root, buffer, pktinfo, offset, matches)
        -- e.g.
        -- line => *1 or $4 or +OK or +PONG
        local line = matches() -- get next line
        local length = line:len()

        local prefix, text = line:match('([-+:$*])(.+)')

        local mtype = mtypes[prefix]

        assert(prefix and text, 'unrecognized line: '..line)
        assert(mtype, 'unrecognized message type: '..prefix)

        if prefix == '*' then    -- Arrays, contains multiple Bulk Strings

            local num_of_bulk = tonumber(text)

            -- this is a bit gross: we parse (part of) the buffer again to
            -- calculate the length of the entire multi-bulk message
            -- if we don't do this, Wireshark will highlight only our prologue
            local bytes = 0
            local remainder = buffer():string():sub(offset + length + CRLF)
            local submatches = remainder:gmatch('[^\r\n]+')
            --local submatches = remainder:gmatch('([^\r]+)\r\n')

            local d = {}
            local counter = num_of_bulk
            while counter > 0 do
                local submatch = submatches() -- get next line
                if submatch:sub(1,1) ~= '$' then -- Bulk Strings contain an extra CRLF
                    table.insert(d, submatch)
                    counter = counter - 1
                end
                bytes = bytes + submatch:len() + CRLF
            end

            for k, v in ipairs(d) do
                d[k] = tostring(v)
            end

            command = table.concat(d, " ")
            io.write(command.."\n")

            local child = root:add(proto, buffer(offset, length + CRLF + bytes), 'Redis Request')
            offset = offset + length + CRLF
            -- offset = offset + length + CRLF + bytes

            -- recurse down for each message contained in this multi-bulk message
            
            for ii = 1, num_of_bulk do
                offset = recurse(child, buffer, pktinfo, offset, matches)
            end

            io.write("-----\n")
            
            pktinfo.cols.info:set("Redis Request")
            pktinfo.cols.info:append(" ".."\t--> ".."("..command..")")

        elseif prefix == '$' then -- bulk, contains one binary string

            -- io.write("len: "..length.."   matches: "..line.."\n")

            local bytes = tonumber(text)
            
            if bytes == -1 then
                local child = root:add(proto, buffer(offset, length + CRLF), 'Redis Response')

                offset = offset + length + CRLF

                child:add(f.value, '<null>')
            else
                local child = root:add(proto, buffer(offset, length + CRLF + bytes + CRLF), 'Redis Response')

                offset = offset + length + CRLF

                -- get the string contained within this bulk message
                local line = matches()
                local length = line:len()
                child:add(f.value, buffer(offset, length))
                offset = offset + length + CRLF
            end

            pktinfo.cols.info:set("Redis Response")

        else -- integer, status or error
            local child = root:add(proto, buffer(offset, length + CRLF), 'Redis Response')
            buf = buffer(offset + prefix:len(), length - prefix:len())
            child:add(f.value, buf)
            offset = offset + length + CRLF

            io.write(buf:string().."\n")

            pktinfo.cols.info:set("Redis Response")
            pktinfo.cols.info:append(" ".."\t--> ".."("..buf:string()..")")

        end

        return offset
    end

----


    function proto.dissector(tvbuf, pktinfo, root)
        pktinfo.cols.protocol:set('Redis')

        -- parse top-level messages until the tvbuf is exhausted
        local matches = tvbuf():string():gmatch('[^\r\n]+')
        --local matches = tvbuf():string():gmatch('([^\r]+)\r\n')
        local offset = 0
        while offset < tvbuf():len() do
            offset = recurse(root, tvbuf, pktinfo, offset, matches)
        end

        -- check that we consumed exactly the right number of bytes
        assert(offset == tvbuf():len(), 'consumed '..offset..' bytes of '..tvbuf():len())
    end

    -- register this dissector for the standard Redis ports
    local dissectors = DissectorTable.get('tcp.port')

    for _, port in ipairs{ 6379, 7106, 7108 } do
        dissectors:add(port, proto)
    end
end
