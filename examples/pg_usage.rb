# frozen_string_literal: true

require "pg"

# PG.connect drives the PostgreSQL v3 protocol over an injected IO-like object
# (rbgo has no native socket yet). FakeSock replays a canned backend byte stream
# so this example runs offline; against a real server you pass a live socket.
class FakeSock
  def initialize(reply)
    @in = reply.dup.force_encoding("ASCII-8BIT")
    @pos = 0
  end

  def write(s) = s.bytesize # server ignores the bytes we send in this demo

  def read(n = nil)
    avail = @in.bytesize - @pos
    return "".b if avail <= 0
    n = avail if n.nil? || n > avail
    chunk = @in.byteslice(@pos, n)
    @pos += n
    chunk
  end
end

# Build one wire message: type byte + big-endian Int32 length + body.
def frame(type, body) = (type + [body.b.bytesize + 4].pack("N") + body.b).b

def row_desc(cols)
  body = [cols.size].pack("n").b
  cols.each { |name, oid| body << name.b << "\x00".b << [0, 0, oid, -1, -1, 0].pack("Nn Nn Nn") }
  frame("T", body)
end

def data_row(vals)
  body = [vals.size].pack("n").b
  vals.each { |v| v.nil? ? body << [-1].pack("N") : body << [v.b.bytesize].pack("N") << v.b }
  frame("D", body)
end

# Handshake (AuthenticationOk + ReadyForQuery) then a two-row result set.
reply = frame("R", [0].pack("N")) + frame("Z", "I") +
        row_desc([["id", 23], ["name", 25]]) +
        data_row(["1", "Ada"]) + data_row(["2", nil]) +
        frame("C", "SELECT 2\x00") + frame("Z", "I")

conn = PG.connect(connection: FakeSock.new(reply), user: "me", dbname: "app")

# #exec runs a simple query and returns a PG::Result.
res = conn.exec("SELECT id, name FROM users")
puts "rows=#{res.ntuples} cols=#{res.fields.join(",")} status=#{res.cmd_status}"

# Read cells by position, detect SQL NULL, or take a whole row as a Hash.
puts "getvalue(0,1) => #{res.getvalue(0, 1)}"          # => Ada
puts "row 1 name NULL? #{res.getisnull(1, 1)}"         # => true
res.each { |row| puts "  #{row["id"]}: #{row["name"].inspect}" }

# #escape_string / #quote_ident are the pure string-quoting helpers.
puts "escaped literal : #{conn.escape_string("O'Brien")}"
puts "quoted ident    : #{conn.quote_ident("user name")}"

conn.finish
