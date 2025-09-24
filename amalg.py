class Amalgamator:
    def __init__(self):
        self.out = ""

    def append_text(self, text):
        self.out += text

    def append_file(self, file):

        self.out += "\n"
        self.out += "////////////////////////////////////////////////////////////////////////////////////////\n"
        self.out += "// " + file + "\n"
        self.out += "////////////////////////////////////////////////////////////////////////////////////////\n"
        self.out += "\n"
        self.out += "#line 1 \"" + file + "\"\n"
        self.out += open(file).read()

        if len(self.out) > 0 and self.out[len(self.out)-1] != '\n':
            self.out += "\n"

    def save(self, file):
        open(file, 'w').write(self.out)

desc = """
// This file was generated automatically. Do not modify directly!
"""

header = Amalgamator()
header.append_text("#ifndef CWEB_AMALGAMATION\n")
header.append_text("#define CWEB_AMALGAMATION\n")
header.append_text(desc)
header.append_file("src/main.h")
header.append_text("#endif // CWEB_AMALGAMATION\n")
header.save("cweb.h")

source = Amalgamator()
source.append_text("#include \"cweb.h\"\n")
source.append_text("#define WL_NOINCLUDE\n")
source.append_text("#define HTTP_NOINCLUDE\n")
source.append_text("#define CRYPT_BLOWFISH_NOINCLUDE\n")

source.append_file("3p/chttp.h")
source.append_file("3p/chttp.c")

source.append_text("#undef MIN\n")
source.append_text("#undef MAX\n")
source.append_text("#undef ASSERT\n")
source.append_text("#undef SIZEOF\n")
source.append_text("#undef TRACE\n")

source.append_file("3p/sqlite3.c")

source.append_text("#undef MIN\n")
source.append_text("#undef MAX\n")
source.append_text("#undef ASSERT\n")
source.append_text("#undef SIZEOF\n")
source.append_text("#undef TRACE\n")

source.append_text("#define Scanner WL_Scanner\n")
source.append_text("#define Token WL_Token\n")
source.append_text("#define is_space is_space__wl\n")
source.append_text("#define is_digit is_digit__wl\n")
source.append_text("#define is_alpha is_alpha__wl\n")
source.append_text("#define is_printable is_printable__wl\n")
source.append_text("#define is_hex_digit is_hex_digit__wl\n")
source.append_text("#define hex_digit_to_int hex_digit_to_int__wl\n")
source.append_text("#define consume_str consume_str__wl\n")

source.append_file("3p/wl.h")
source.append_file("3p/wl.c")

source.append_text("#undef Scanner\n")
source.append_text("#undef Token\n")
source.append_text("#undef is_space\n")
source.append_text("#undef is_digit\n")
source.append_text("#undef is_alpha\n")
source.append_text("#undef is_printable\n")
source.append_text("#undef is_hex_digit\n")
source.append_text("#undef hex_digit_to_int\n")

source.append_text("#undef MIN\n")
source.append_text("#undef MAX\n")
source.append_text("#undef ASSERT\n")
source.append_text("#undef SIZEOF\n")

source.append_file("3p/crypt_blowfish.h")
source.append_file("3p/crypt_blowfish.c")
source.append_file("src/main.c")
source.save("cweb.c")
