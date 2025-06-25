--  ------------------------------------------------------------------------------------
--  Wireshark dissector for TCP communication of the MVRxchange protocol
--  Place it into your Wireshark "Personal Lua Plugins" folder as set in
--  Wireshark → Help → About Wireshark → Folders → Personal Lua Plugins
--  Adds a new protocol named "mvrxchange".
--  Requires: json.lua
--
--  Petr Vaněk @ Robe Lighting
--  ------------------------------------------------------------------------------------

--  ------------------------------------------------------------------------------------
--  Protocol Column now shows "MVR"
--  Info Column shows mvr packet type and station's name in the following format:
--      <type> | <station_name>
--  MVR relavant information in the Packet Details pane now shows information with
--  appropriate spacing.
--
--  Luke Chikkala @ MA Lighting International GmbH
--  ------------------------------------------------------------------------------------
--  Formatting style: use lua54 stylua formatter from https://github.com/JohnnyMorganz/StyLua
--  Installation: cargo install stylua --features lua54
--  Usage: stylua mvrxchange.lua

local mvrxchange = Proto("mvrxchange", "MVRxchange")
json = require("json")

local mvr_fields = mvrxchange.fields
local station_name_table = {}

mvr_fields.header = ProtoField.uint32("mvrxchange.header", "Header", base.HEX)
mvr_fields.version = ProtoField.uint32("mvrxchange.version", "Version", base.DEC)
mvr_fields.number = ProtoField.uint32("mvrxchange.number", "Number", base.DEC)
mvr_fields.count = ProtoField.uint32("mvrxchange.count", "Count", base.DEC)
mvr_fields.type = ProtoField.uint32("mvrxchange.type", "Type", base.DEC)
mvr_fields.length = ProtoField.uint64("mvrxchange.length", "Length", base.DEC)
mvr_fields.real_length = ProtoField.string("mvrxchange.real_length", "Real Length ")

mvr_fields.message = ProtoField.string("mvrxchange.message", "MVR Message ")
mvr_fields.message_type = ProtoField.string("mvrxchange.message_type", "Type")
mvr_fields.message_ok = ProtoField.string("mvrxchange.message_ok", "Ok")
mvr_fields.message_message = ProtoField.string("mvrxchange.message_message", "Message")
mvr_fields.message_provider = ProtoField.string("mvrxchange.provider", "Provider")
mvr_fields.message_station_name = ProtoField.string("mvrxchange.message_station_name", "Station Name")
mvr_fields.message_ver_major = ProtoField.string("mvrxchange.message_ver_major", "Ver Major")
mvr_fields.message_ver_minor = ProtoField.string("mvrxchange.message_ver_minor", "Ver Minor")
mvr_fields.message_comment = ProtoField.string("mvrxchange.message_comment", "Comment")
mvr_fields.message_commits = ProtoField.string("mvrxchange.message_commits", "Commits")
mvr_fields.message_commit = ProtoField.string("mvrxchange.message_commit", "Commit")
mvr_fields.message_files = ProtoField.string("mvrxchange.message_files", "Files")
mvr_fields.message_station_uuid = ProtoField.string("mvrxchange.message_station_uuid", "Station UUID")
mvr_fields.message_for_station_uuid = ProtoField.string("mvrxchange.message_for_station_uuid", "For Station UUID ")
mvr_fields.message_from_station_uuid = ProtoField.string("mvrxchange.message_from_station_uuid", "From Station UUID ")
mvr_fields.message_file_size = ProtoField.string("mvrxchange.message_file_size", "File Size")
mvr_fields.message_file_uuid = ProtoField.string("mvrxchange.message_file_uuid", "File UUID")
mvr_fields.message_file_comment = ProtoField.string("mvrxchange.message_file_comment", "File Comment")
mvr_fields.message_file_file_name = ProtoField.string("mvrxchange.message_file_file_name", "File Name")
mvr_fields.message_errors = ProtoField.string("mvrxchange.message_errors", "Errors")
mvr_fields.message_service_name = ProtoField.string("mvrxchange.service_name", "ServiceName")
mvr_fields.message_service_url = ProtoField.string("mvrxchange.service_url", "ServiceURL")

function process_message(data, subtree)
	subtree:add(mvr_fields.message_type):append_text(data["Type"])

	if data["OK"] ~= nil then
		subtree:add(mvr_fields.message_ok):append_text(tostring(data["OK"]))
	end
	if data["Message"] ~= nil then
		subtree:add(mvr_fields.message_message):append_text(data["Message"])
	end
	if data["Provider"] ~= nil then
		subtree:add(mvr_fields.message_provider):append_text(data["Provider"])
	end
	if data["verMinor"] ~= nil then
		subtree:add(mvr_fields.message_ver_minor):append_text(data["verMinor"])
	end
	if data["verMajor"] ~= nil then
		subtree:add(mvr_fields.message_ver_major):append_text(data["verMajor"])
	end
	if data["FileSize"] ~= nil then
		subtree:add(mvr_fields.message_file_size):append_text(data["FileSize"])
	end
	if data["FileName"] ~= nil then
		subtree:add(mvr_fields.message_file_file_name):append_text(data["FileName"])
	end
	if data["ForStationUUID"] ~= nil then
		local uuids = data["ForStationUUID"]
		if type(uuids) == "table" then
			if #uuids > 0 then
				for _, uuid in ipairs(uuids) do
					subtree:add(mvr_fields.message_from_station_uuid):append_text(uuid)
				end
			else
				subtree:add(mvr_fields.message_from_station_uuid):append_text("[]")
			end
		end
	end

	if data["Comment"] ~= nil then
		subtree:add(mvr_fields.message_comment):append_text(data["Comment"])
	end
	if data["Commits"] ~= nil then
		local commits = subtree:add(mvr_fields.message_commits)

		if type(data["Commits"]) == "table" and #data["Commits"] > 0 then
			commits:append_text("" .. tostring(#data["Commits"]) .. "")
			for k, v in pairs(data["Commits"]) do
				-- print("Commit", v.Type, v.FileUUID, v.StationUUID, v.Comment, v.FileName, v.FileSize)
				local commit = commits:add(mvr_fields.message_commit):append_text(v.FileUUID)
				if v.FileSize ~= nil then
					commit:add(mvr_fields.message_file_size):append_text(v.FileSize)
				end
				if v.Comment ~= nil then
					commit:add(mvr_fields.message_file_comment):append_text(v.Comment)
				end
				if v.FileName ~= nil then
					commit:add(mvr_fields.message_file_file_name):append_text(v.FileName)
				end
				commit:add(mvr_fields.message_type):append_text(v.Type)
				commit:add(mvr_fields.message_station_uuid):append_text(v.StationUUID)
				commit:add(mvr_fields.message_ver_major):append_text(v.verMajor)
				commit:add(mvr_fields.message_ver_minor):append_text(v.verMinor)
				for k, v in pairs(v["ForStationsUUID"]) do
					commit:add(mvr_fields.message_for_station_uuid):append_text(v.ForStationsUUID)
				end
			end
		else
			commits:append_text("[]")
		end
	end
	if data["Files"] ~= nil then
		errsubtree = subtree:add(mvr_fields.message_files):append_text("Number:" .. tostring(#data["Files"]) .. "")
		errsubtree:add_expert_info(PI_MALFORMED, PI_WARN, "Wrong field, should be Commits")
	end
	if data["StationName"] ~= nil then
		subtree:add(mvr_fields.message_station_name):append_text(data["StationName"])
	end
	if data["StationUUID"] ~= nil then
		errsubtree = subtree:add(mvr_fields.message_station_uuid):append_text(data["StationUUID"])
		if (data["StationUUID"] == "00000000-0000-0000-0000-000000000000") or (data["StationUUID"] == "") then
			errsubtree:add_expert_info(PI_MALFORMED, PI_WARN, "UUID should not be empty or 0")
		end
	end
	if data["FileUUID"] ~= nil then
		errsubtree = subtree:add(mvr_fields.message_file_uuid):append_text(data["FileUUID"])
		if data["FileUUID"] == "00000000-0000-0000-0000-000000000000" then
			errsubtree:add_expert_info(PI_MALFORMED, PI_WARN, "UUID can be empty or UUID but should not be 0")
		end
	end

	if data["FromStationUUID"] ~= nil then
		local uuids = data["FromStationUUID"]

		if is_not_table(uuids) then
			-- Handle the case where FromStationUUID is not a table
			local errsubtree = subtree:add(mvr_fields.message_from_station_uuid):append_text(uuids)
			if uuids == "" then
				errsubtree:add_expert_info(PI_MALFORMED, PI_WARN, "Should not be empty")
			end
		elseif type(uuids) == "table" then
			-- Handle the case where FromStationUUID is a table
			if #uuids > 0 then
				for _, uuid in ipairs(uuids) do
					subtree:add(mvr_fields.message_from_station_uuid):append_text(uuid)
				end
			else
				subtree:add(mvr_fields.message_from_station_uuid):append_text("[]") -- Display empty array indicator
			end
		end
	end

	if data["ServiceName"] ~= nil then
		subtree:add(mvr_fields.message_service_name):append_text(data["ServiceName"])
	end
	if data["ServiceURL"] ~= nil then
		subtree:add(mvr_fields.message_service_url):append_text(data["ServiceURL"])
	end
end

function get_stored_station_name(key_src, key_dst)
	local stored_station_name_src = station_name_table[key_src]
	local stored_station_name_dst = station_name_table[key_dst]
	local result
	if stored_station_name_src then
		result = stored_station_name_src
	elseif stored_station_name_dst then
		result = stored_station_name_dst
	end
	return result
end

function mvrxchange.dissector(tvbuf, pinfo, tree)
	local mvr_type = tvbuf(16, 4)
	local message = tvbuf(28, len)
	local info = pinfo.cols.info

	--  ------------------------------------------------------------------------------------
	--  Sets Protocol column to "MVR"
	--  ------------------------------------------------------------------------------------
	pinfo.cols.protocol = "MVR"
	--  ------------------------------------------------------------------------------------

	--  ------------------------------------------------------------------------------------
	--  Clears any enforced messages from Wireshark to allow for clean printing our
	--  messages.
	--  ------------------------------------------------------------------------------------
	info:clear_fence()
	--  ------------------------------------------------------------------------------------

	local t = tree:add(mvrxchange, tvbuf, "")
	t:add(mvr_fields.header, tvbuf(0, 4))
	t:add(mvr_fields.version, tvbuf(4, 4))
	t:add(mvr_fields.number, tvbuf(8, 4))
	t:add(mvr_fields.count, tvbuf(12, 4))
	t:add(mvr_fields.type, mvr_type)
	t:add(mvr_fields.length, tvbuf(20, 8))
	t:add(mvr_fields.real_length, tvbuf(28, len):len())

	local src_ip = pinfo.src
	local src_port = pinfo.src_port
	local dst_port = pinfo.dst_port
	local key_src = tostring(src_ip) .. ":" .. tostring(src_port)
	local key_dst = tostring(src_ip) .. ":" .. tostring(dst_port)

	if mvr_type:uint() == 0 and message:len() > 2 then
		local s = t:add(mvr_fields.message)
		-- print( "Message", message:string() )
		local decoded = json.decode(message:string())

		local mvr_type = decoded["Type"]
		local type_length = #mvr_type

		if decoded["Type"] ~= nil then
			if decoded["StationName"] ~= nil then
				local mvr_station_name = decoded["StationName"]
				station_name_table[key_src] = mvr_station_name
				station_name_table[key_dst] = mvr_station_name
				info:set(mvr_type .. string.rep(" ", 21 - type_length) .. " | " .. mvr_station_name)
			else
				local stored_station_name = get_stored_station_name(key_src, key_dst)
				if stored_station_name then
					info:set(mvr_type .. string.rep(" ", 21 - type_length) .. " | " .. stored_station_name)
				else
					info:set(mvr_type .. string.rep(" ", 21 - type_length))
				end
			end
		end

		-- ------------------------------------------------------------------------------------

		process_message(decoded, s)
	else
		local stored_station_name = get_stored_station_name(key_src, key_dst)
		local mvr_file_transfer_label = "MVR File Transfer"
		local type_length = #mvr_file_transfer_label

		if stored_station_name then
			info:set(mvr_file_transfer_label .. string.rep(" ", 21 - type_length) .. " | " .. stored_station_name)
		else
			info:set(mvr_file_transfer_label)
		end

		t:add(mvr_fields.message, tvbuf(0, 0)):append_text(mvr_file_transfer_label)
	end
end

local function heuristic_checker(buffer, pinfo, tree)
	length = buffer:len()
	if length < 4 then
		return false
	end

	local header = buffer(0, 4):uint()

	if header == 778682 then
		mvrxchange.dissector(buffer, pinfo, tree)
		return true
	else
		return false
	end
end

function is_not_table(t)
	return type(t) ~= "table"
end

mvrxchange:register_heuristic("tcp", heuristic_checker)
