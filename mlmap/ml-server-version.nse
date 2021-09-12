local http = require "http"
local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"
local json = require "json"

local openssl = stdnse.silent_require "openssl"

description = [[
Attemps to identify the deployment server and framework of a machine learning deployment. 

TODO:
- Use magic queries to identify the TensorFlow serve versions.
- Bruteforce the model names
- Use magic queries to try to identfy the dataset used for a model and the model type.
]]

---
-- @output
-- PORT   STATE SERVICE REASON
-- 8443/tcp open  http    syn-ack
-- | ml-framework: PyTorch
-- | server: TorchServe
-- | Versions from Signature: 0.4.2
-- |_Model type: DNN


author = {"Adelin Travers"}
license = "Simplified (2-clause) BSD license--See https://nmap.org/svn/docs/licenses/BSD-simplified"
categories = {"discovery", "safe"}


--portrule = shortport.http
portrule = function(host, port)
	return port.protocol == "tcp"
		and port.state == "open"
end
-- For PyTorch

server_candidates = {"TorchServe", "TensorFlow Serving", "MlFlow", "Azure"}
framework_candidates = {"PyTorch", "Tensorflow", "Sklearn"}
--TODO:
--framework_version = {"0.0.0"}
magic_queries = {["TorchServe"] = {"GET","/api-description"},
		 ["TensorFlow Serving"] = {"POST", "/v1/models/*:predict", "{\"instances\": [1.0,5.0]}"}
	 	}
local function isempty(s)
  return s == nil or s == ''
end

action = function(host, port)
	local response
	local framework_versions_identified
	local framework_identified
	local server_identified
	local header_value, header_name
	local lines

	for framework, magic_query in pairs(magic_queries) do
		print(magic_query[2])
		if magic_query[1] == "POST" then
			response = http.post(host, port, magic_query[2],{ no_cache = true }, nil, magic_query[3])
		end

		if magic_query[1] == "GET" then
			response = http.get(host, port, magic_query[2])
		end

		if string.match(response.body, "TorchServe") then
			framework_identified = {framework_candidates[1]}
			server_identified = {server_candidates[1]}
			local parsing_status, parsed = json.parse(response.body)
			framework_versions_identified = {parsed.info.version} 
		end
		if string.match(response.body, "Servable") then
			framework_identified = {framework_candidates[2]}
			server_identified = {server_candidates[2]}
		end

	end

	lines = {}
	if framework_identified then
		lines[#lines + 1] = "\nml-framework:" .. table.concat(framework_identified, ", ")
		lines[#lines + 1] = "server:" .. table.concat(server_identified, ", ")
		if isempty(framework_versions_identified) then
			framework_versions_identified={'No version identified'}
		end
		lines[#lines + 1] = "Versions from Signature: " .. table.concat(framework_versions_identified, ", ")
	end
	
	if #lines > 0 then
		return table.concat(lines, "\n")
	end
end
