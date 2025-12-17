local md5_lib = require 'libs/md5' -- from https://github.com/kikito/md5.lua

local p_miio = Proto("miio", "Xiaomi Mi Home Binary Protocol")

local fieldlist = {
  {"Device ID", "Device ID (decimal or hex started with 0x)"},
  {"Token", "128-bit device token (in hex)"},
}
p_miio.prefs.device_tokens = Pref.uat("Miio device tokens", fieldlist, "Miio device tokens", "miio_device_tokens")


local f_magic = ProtoField.uint16("miio.magic", "Magic", base.HEX)
local f_length = ProtoField.uint16("miio.length", "Length", base.DEC)
local f_unknown = ProtoField.uint32("miio.unknown", "Unknown", base.HEX)
local f_deviceId = ProtoField.uint32("miio.deviceId", "DeviceID", base.HEX)
local f_ts = ProtoField.uint32("miio.ts", "Timestamp", base.DEC)
local f_checksum = ProtoField.bytes("miio.checksum", "Checksum")
local f_encryptd_data = ProtoField.bytes("miio.encryptd_data", "Encrypted data")
local f_decrypted_data = ProtoField.string("miio.data", "Data")
p_miio.fields = { f_magic, f_length, f_unknown, f_deviceId, f_ts, f_checksum, f_encryptd_data, f_decrypted_data }

local ef_unknown_payload_encoding = ProtoExpert.new(
  "miio.unknown_payload_encoding",
  "Unknown payload encoding",
  expert.group.DECRYPTION,
  expert.severity.WARN
)
p_miio.experts = { ef_unknown_payload_encoding }

local token_map = {}
local function rebuild_token_map()
  token_map = {}
  for _, row in ipairs(p_miio.prefs.device_tokens) do
    local device_id = tonumber(row[1])
    local token = row[2]
    token_map[device_id] = token
  end
end
local function get_token(device_id)
  return token_map[device_id]
end
function p_miio.init()
  rebuild_token_map()
end

local function md5(str)
  local b = ByteArray.new(str):raw()
  return md5_lib.sumhexa(b)
end

local function remove_padding(decrypted_ba)
  -- PKCS#7 Padding
  local BLOCK_SIZE = 16
  local len = decrypted_ba:len()

  -- 1. Check if the length is a multiple of the block size (it should be)
  if (len % BLOCK_SIZE ~= 0) then
    -- Handle error: Decryption failed or data is corrupted
    warn("Decrypted data length is not a multiple of block size!")
    return decrypted_ba
  end

  -- 2. Read the value of the *last* byte, which tells you the padding length (P).
  local padding_length = decrypted_ba:get_index(len - 1)

  -- 3. Validate the padding length
  if (padding_length < 1 or padding_length > BLOCK_SIZE) then
    -- Handle error: Padding length is invalid. This is often an indication
    -- that the wrong key was used (a "padding oracle" failure).
    warn("PKCS#7 padding length is invalid: " .. padding_length)
    return decrypted_ba
  end

  -- 4. (Optional but recommended) Verify all padding bytes have the correct value
  for i = 1, padding_length do
    -- Check byte at index (len - i)
    if (decrypted_ba:get_index(len - i) ~= padding_length) then
        warn("PKCS#7 padding validation failed at byte " .. i)
        return decrypted_ba
    end
  end

  -- 5. Strip the padding.
  return decrypted_ba:subset(0, len - padding_length)
end

local function aes_128_cbc_decrypt(data, key, iv)
  local cipher = GcryptCipher.open(GCRY_CIPHER_AES, GCRY_CIPHER_MODE_CBC, 0)
  cipher:setkey(ByteArray.new(key))
  cipher:setiv(ByteArray.new(iv))
  local decrypted = cipher:decrypt(nil, data)
  return remove_padding(decrypted)
end

local function miio_dissector(buf, pkt, root)
  if buf:len() < 32 then return false end

  local magic = buf(0, 2)
  if magic:uint() ~= 0x2131 then return false end

  local len = buf(2, 2)
  if buf:len() < len:uint() then return false end

  pkt.cols.protocol = "MIIO"

  local unknown = buf(4, 4)
  local deviceId = buf(8, 4)
  local ts = buf(12, 4)
  local checksum = buf(16, 16)

  local t = root:add(p_miio, buf(0, len:uint()))
  if len:uint() == 32 then
    if deviceId:uint() == 0xffffffff then
      pkt.cols.info = "Hello"
    else
      pkt.cols.info = "Hello Ack"
    end
  end

  t:add(f_magic, magic)
  t:add(f_length, len)
  t:add(f_unknown, unknown)
  t:add(f_deviceId, deviceId)
  t:add(f_ts, ts)
  t:add(f_checksum, checksum)

  if len:uint() > 32 then
    local data = buf(32, len:uint() - 32)
    local token = get_token(deviceId:uint())
    if (token ~= nil and token ~= "") then
      local key = md5(token)
      local iv = md5(string.format("%s%s", key, token))
      local decrypted_data = aes_128_cbc_decrypt(data:bytes(), key, iv)
      -- TODO trim && check valid
      local decrypted_data_tvb = decrypted_data:tvb("Decrypted Data")
      t:add(f_decrypted_data, decrypted_data_tvb:range(), "", string.format("Data: %d bytes", decrypted_data:len()))

      if decrypted_data:get_index(0) == string.byte('{') then
        Dissector.get("json"):call(decrypted_data_tvb, pkt, root)
        pkt.cols.info = decrypted_data:raw()
      else
        pkt.cols.info = "MIIO: Unknown payload encoding"
        t:add_proto_expert_info(ef_unknown_payload_encoding)
        local data_dis = Dissector.get("data")
        data_dis:call(decrypted_data_tvb, pkt, root)
      end
    else
      t:add(f_encryptd_data, data)
    end
  end

  return true
end


local data_dis = Dissector.get("data")
function p_miio.dissector(buf, pkt, root)
  if miio_dissector(buf, pkt, root) then
    --valid MIIO diagram
  else
    data_dis:call(buf, pkt, root)
  end
end

local udp_encap_table = DissectorTable.get("udp.port")
udp_encap_table:add(54321, p_miio)
