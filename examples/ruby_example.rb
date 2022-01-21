  # ruleid: file-disclosure
    config.serve_static_assets = true

require 'open3'

def test_calls(user_input)
# ruleid: dangerous-exec
  exec("ls -lah #{user_input}")

# ruleid: dangerous-exec
  Process.spawn([user_input, "smth"])

# ruleid: dangerous-exec
  output = exec(["sh", "-c", user_input])

# ruleid: dangerous-exec
  pid = spawn(["bash", user_input])

  commands = "ls -lah /raz/dva"
# ok: dangerous-exec
  system(commands)

  cmd_name = "sh"
# ok: dangerous-exec
  Process.exec([cmd_name, "ls", "-la"])
# ok: dangerous-exec
  Open3.capture2({"FOO" => "BAR"}, [cmd_name, "smth"])
# ok: dangerous-exec
  system("ls -lah /tmp")
# ok: dangerous-exec
  exec(["ls", "-lah", "/tmp"])
end

# ruleid:dangerous-open
cmd = open("|%s" % user_input)
print cmd.gets
cmd.close

# ruleid:dangerous-open
cmd = open(Kernel::sprintf("|%s", user_input))
print cmd.gets
cmd.close


class Person
end

# ruleid:ruby-eval
Person.class_eval do
  def say_hello
   "Hello!"
  end
end

jimmy = Person.new
jimmy.say_hello # "Hello!"

# ruleid:ruby-eval
Person.instance_eval do
  def human?
    true
  end
end

Person.human? # true

# ruleid:ruby-eval
Array.class_eval(array_second)



class Account < ActiveRecord::Base
  validates_format_of :name, :with => /^[a-zA-Z]+$/
  validates_format_of :blah, :with => /\A[a-zA-Z]+$/
  validates_format_of :something, :with => /[a-zA-Z]\z/
  validates_format_of :good_valid, :with => /\A[a-zA-Z]\z/ #No warning
  validates_format_of :not_bad, :with => /\A[a-zA-Z]\Z/ #No warning

  def mass_assign_it
    Account.new(params[:account_info]).some_other_method
  end

  def test_class_eval
    # ruleid:ruby-eval
    User.class_eval do
      attr_reader :some_private_thing
    end
  end
end

def zen
  41
end

# ruleid:ruby-eval
eval("def zen; 42; end")

puts zen

class Thing
end
a = %q{def hello() "Hello there!" end}
# ruleid:ruby-eval
Thing.module_eval(a)
puts Thing.new.hello()


def get_binding(param)
  binding
end
b = get_binding("hello")
# ruleid:ruby-eval
b.eval("param")

# ruleid:ruby-eval
RubyVM::InstructionSequence.compile("1 + 2").eval

iseq = RubyVM::InstructionSequence.compile('num = 1 + 2')
# ruleid:ruby-eval
iseq.eval

require 'digest'
class bad_md5
    def bad_md5_code()
        # ruleid: weak-hashes-md5
        md5 = Digest::MD5.hexdigest 'abc'
        # ruleid: weak-hashes-md5
        md5 = Digest::MD5.new
        # ruleid: weak-hashes-md5
        md5 = Digest::MD5.base64digest 'abc'
        # ruleid: weak-hashes-md5
        md5 = Digest::MD5.digest 'abc'

        # ruleid: weak-hashes-md5
        digest = OpenSSL::Digest::MD5.new
        # ruleid: weak-hashes-md5
        digest = OpenSSL::Digest::MD5.hexdigest 'abc'
        # ruleid: weak-hashes-md5
        digest = OpenSSL::Digest::MD5.new
        # ruleid: weak-hashes-md5
        digest = OpenSSL::Digest::MD5.base64digest 'abc'
        # ruleid: weak-hashes-md5
        digest = OpenSSL::Digest::MD5.digest 'abc'
    end
end

require 'digest'
class bad_md5
    def bad_md5_code()
        # ruleid: weak-hashes-sha1
        sha = Digest::SHA1.hexdigest 'abc'
        # ruleid: weak-hashes-sha1
        sha = Digest::SHA1.new
        # ruleid: weak-hashes-sha1
        sha = Digest::SHA1.base64digest 'abc'
        # ruleid: weak-hashes-sha1
        sha = Digest::SHA1.digest 'abc'

        # ruleid: weak-hashes-sha1
        digest = OpenSSL::Digest::SHA1.new
        # ruleid: weak-hashes-sha1
        digest = OpenSSL::Digest::SHA1.hexdigest 'abc'
        # ruleid: weak-hashes-sha1
        digest = OpenSSL::Digest::SHA1.new
        # ruleid: weak-hashes-sha1
        digest = OpenSSL::Digest::SHA1.base64digest 'abc'
        # ruleid: weak-hashes-sha1
        digest = OpenSSL::Digest::SHA1.digest 'abc'
        # ruleid: weak-hashes-sha1
        OpenSSL::HMAC.hexdigest("sha1", key, data)
        # ok: weak-hashes-sha1
        OpenSSL::HMAC.hexdigest("SHA256", key, data)
        # ok: weak-hashes-sha1
        digest = OpenSSL::Digest::SHA256.new
        # ok: weak-hashes-sha1
        digest = OpenSSL::Digest::SHA256.hexdigest 'abc'
    end
end

def bad_deserialization
    o = Klass.new("hello\n")
    data = Marshal.dump(o)
    # ruleid: bad-deserialization
    obj = Marshal.load(data)

    o = Klass.new("hello\n")
    data = YAML.dump(o)
    # ruleid: bad-deserialization
    obj = YAML.load(data)

    o = Klass.new("hello\n")
    data = CSV.dump(o)
    # ruleid: bad-deserialization
    obj = CSV.load(data)

    o = Klass.new("hello\n")
    data = CSV.dump(o)
    # ruleid: bad-deserialization
    obj = data.object_load()
 end

 def ok_deserialization
    o = Klass.new("hello\n")
    data = YAML.dump(o)
    # ok: bad-deserialization
    obj = YAML.load(data, safe: true)

    filename = File.read("test.txt")
    data = YAML.dump(filename)
    # ok: bad-deserialization
    YAML.load(filename)

    # ok: bad-deserialization
    YAML.load(File.read("test.txt"))
 end


