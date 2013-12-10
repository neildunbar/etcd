local j = require "cjson"
local d = require "dump"
local io = require "io"
local os = require "os"
local lp = require "posix"
local s = require "string"
local m = require "math"
local bit = require "bit"

function get_cert_name(dumpcert)
   tmp = os.getenv("TMPDIR") or '/tmp'

   -- set a restrictive umask to try and prevent data leakage
   omask = lp.umask("rwx------")
   p = lp.mkdtemp(tmp .. "/lua-cparse.XXXXXX")
   tf = nil
   while tf == nil do
      r = m.random(1,16777215) -- 6 digit hex number
      tfname = p .. s.format('/parse.out.%06x', r)
      tf = lp.open(tfname, bit.bor(lp.O_WRONLY,lp.O_CREAT,lp.O_TRUNC,lp.O_EXCL), "rw-------")
      if tfname ~= nil then
         lp.close(tf)
      end
   end
   cmdname = dumpcert .. " > " .. tfname

   -- I know - horrible race conditions abound here. All I really want
   -- is a popen2 implementation for dump-certname, but various lua
   -- discussions indicate that's not a reasonable idea.

   -- dump certificate name (in JSON) to a unique file
   rh = io.popen(cmdname, "w")
   rh:write(io.read("*a"))
   rh:close()
   -- now read that file back into memory
   jsfile = io.open(tfname,"r")
   t = jsfile:read("*a")
   jsfile:close()
   -- decode the JSON
   cname = j.decode( t )

   -- clean up the temporary file and directory
   lp.unlink(tfname)
   lp.rmdir(p)
   -- reset the umask
   lp.umask(omask)

   return cname
end

function main()
   dumpcert = os.getenv("DUMPCERT") or "/usr/bin/dump-certname"
   cname = get_cert_name(dumpcert)

   print (d.tostring(cname))
end

main()
