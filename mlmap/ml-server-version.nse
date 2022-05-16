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
		 ["TensorFlow Serving"] = {"POST", "/v1/models/*:predict", "{\"instances\": [1.0,5.0]}"},
		 ["MlFlow"] = {"POST", "/invocations", "{\"columns\":[\"alcohol\", \"chlorides\", \"citric acid\", \"density\", \"fixed acidity\", \"free sulfur dioxide\", \"pH\", \"residual sugar\", \"sulphates\", \"total sulfur dioxide\", \"volatile acidity\"],\"data\":[[12.8, 0.029, 0.48, 0.98, 6.2, 29, 3.33, 1.2, 0.39, 75, 0.66]]}",{ ["Content-Type"] = "application", ["format"] = "pandas-split"}}
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
		-- Set the queries options
		local options ={header={},no_cache={}}
		options['header']['User-Agent'] =  "curl/7.83.0"
		options["no_cache"] = true
		-- Set the headers that are defined in the magic queries
		if not isempty(magic_query[4]) then
			for header_name, header_value in pairs(magic_query[4]) do
				options["header"][header_name]=header_value
			end
		end
		if magic_query[1] == "POST" then
			response = http.post(host, port, magic_query[2], options, nil, magic_query[3])
		end

		if magic_query[1] == "GET" then
			response = http.get(host, port, magic_query[2], options)
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
		if string.match(response.body, "This predictor only supports the following content types and formats") then
			server_identified = {server_candidates[3]}
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
	if isempty(framework_identified) then
		-- Some servers like MlFlow support multiple frameworks. Another framework identifier is then needed
		if server_identified then
			lines[#lines + 1] = "\n  server:" .. table.concat(server_identified, ", ")
		end
		lines[#lines + 1] = "  Framework was not identified"
	end
	
	if #lines > 0 then
		return table.concat(lines, "\n")
	end
end
