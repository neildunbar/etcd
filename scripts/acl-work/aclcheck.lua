local j = require "cjson"
local d = require "dump"
local io = require "io"
local os = require "os"
local lp = require "posix"
local str = require "string"
local m = require "math"
local bit = require "bit"
local md5 = require "md5"
local http = require "socket.http"
local rex = require "rex_pcre"

function get_cert_name(dumpcert)
   tmp = os.getenv("TMPDIR") or '/tmp'

   -- set a restrictive umask to try and prevent data leakage
   omask = lp.umask("rwx------")
   p = lp.mkdtemp(tmp .. "/lua-cparse.XXXXXX")
   tf = nil
   while tf == nil do
      r = m.random(1,16777215) -- 6 digit hex number
      tfname = p .. str.format('/parse.out.%06x', r)
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
   cert = io.read("*a")
   chash = md5.sumhexa(cert)
   rh = io.popen(cmdname, "w")
   rh:write(cert)
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

   return chash,cname
end

function string:split(sSeparator, nMax, bRegexp)
   assert(sSeparator ~= '')
   assert(nMax == nil or nMax >= 1)

   local aRecord = {}

   if self:len() > 0 then
      local bPlain = not bRegexp
      nMax = nMax or -1
      
      local nField=1 nStart=1
      local nFirst,nLast = self:find(sSeparator, nStart, bPlain)
      while nFirst and nMax ~= 0 do
         aRecord[nField] = self:sub(nStart, nFirst-1)
         nField = nField+1
         nStart = nLast+1
         nFirst,nLast = self:find(sSeparator, nStart, bPlain)
         nMax = nMax-1
      end
      aRecord[nField] = self:sub(nStart)
   end

   return aRecord
end

function substitute_captures( s, result, captures )
   -- trivial case, substitute any $0 with the entire string
   local t = s
   t = string.gsub(s,'$0',result)
   for n,s in pairs(captures) do
      local d = math.ceil(n / 2)
      local r = n % 2
      if n % 2 == 1 then
         local e = captures[n+1]
         local sub = string.sub(result, s, e)
         t = string.gsub(t, '$' .. d, sub)
      end
   end
   return t
end

function is_match(val, cond, sval)
   if cond["regex"] == false then
      if cond["nocase"] then
         if cond["value"] == ev then return sval else return nil end
      else
         local lc = str:lower(val)
         local lv = str:lower(cond["value"])
         if lc == lv then return sval else return nil end
      end
   else
      local cf = ""
      if cond["nocase"] then
         cf = "i"
      end

      local re = rex.new(cond["value"], cf)
      local s,e,m = re:exec(val)
      if m ~= nil then
         return substitute_captures(sval, val, m)
      else
         return nil
      end
   end
end

function groups_for_id( uri, authzid )
   local res = {}

   -- scan groups which contain the authzid string
   
   local groupbase = uri .. "/v2/keys/_auth/groups?recursive=true"
   body,c,l = http.request(groupbase)
   if c ~= 200 then
      return res
   end

   local response = j.decode(body)
   if response["node"] == nil or response["node"]["nodes"] == nil then
      return res
   end
   local nodes = response["node"]["nodes"]

   for _,g in pairs(nodes) do
      if g["dir"] == nil then
         local gval = j.decode(g["value"])

         for _,member in pairs(gval) do
            print ("Matching " .. authzid .. " against " .. member .. " in group " .. g["key"])
            if authzid == member then
               table.insert(res, lp.basename(g["key"]))
               break -- can skip scanning the rest of this group
            end
         end
      end
   end

   return res
end

function check_mapping(m, uri, ch, cn)
   local v = cn

   for _,c in pairs(m["conditions"]) do
      for _,field in next,string.split(c["element"],".",nil,false) do
         v = v[field]
         if v == nil or type(v) ~= "table" then return nil end
         -- no such field in cert name (or the type of the object is
         -- not appropriate)
         if type(v[1]) == "string" then
            for _,ev in next,v do
               if type(ev) == "string" then
                  local r = is_match(ev, c, m["id"])
                  if r then
                     return { ["authzid"] = r; ["groups"] = groups_for_id( uri, r ) }
                  end
               end
            end
         end
      end
   end

   return nil
end

function map_cert_name_to_id( ch, cn, uri )
   local res={}

   -- test out connection to backend uri
   body,c,l = http.request(uri .. "/v2/machines")
   if c ~= 200 then
      -- something wrong in etcd land
      res["authzid"] = "!anonymous!"
      res["groups"] = {}
      return res
   end

   body,c,l = http.request(uri .. "/v2/keys/_auth/mapping?recursive=true")
   if c ~= 200 then
      -- something wrong in etcd land
      res["authzid"] = "!anonymous!"
      res["groups"] = {}
      return res
   end

   for k,m in pairs(j.decode(body)["node"]["nodes"]) do
      v = j.decode(m["value"])
      res = check_mapping(v, uri, ch, cn)
      if res then return res end
   end

   return { ["authzid"] = "!anonymous!"; ["groups"] = {} }
end

function main()
   dumpcert = os.getenv("DUMPCERT") or "/usr/bin/dump-certname"
   chash, cname = get_cert_name(dumpcert)
   uri = os.getenv("ETCDURI") or "http://127.0.0.1:4001"

   authzid = map_cert_name_to_id( chash, cname, uri )
   print (j.encode(authzid))
end

main()
