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

header.append_text("""/*
Copyright © 2025 Francesco Cozzuto

Permission is hereby granted, free of charge, to any person obtaining a
copy of this software and associated documentation files (the “Software”),
to deal in the Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute, sublicense,
and/or sell copies of the Software, and to permit persons to whom the
Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included
in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
OTHER DEALINGS IN THE SOFTWARE.
*/
""")

header.append_text("#ifndef CWEB_INCLUDED\n")
header.append_text("#define CWEB_INCLUDED\n")
header.append_file("src/main.h")
header.append_text("#endif // CWEB_INCLUDED\n")

header.append_text("#ifdef CWEB_IMPLEMENTATION\n")

header.append_text("#define CWEB_AMALGAMATION\n")
header.append_text("#define WL_NOINCLUDE\n")
header.append_text("#define HTTP_NOINCLUDE\n")
header.append_text("#define CRYPT_BLOWFISH_NOINCLUDE\n")

header.append_text("#undef MIN\n")
header.append_text("#undef MAX\n")
header.append_text("#undef ASSERT\n")
header.append_text("#undef SIZEOF\n")
header.append_text("#undef TRACE\n")

header.append_file("3p/chttp.h")
header.append_file("3p/chttp.c")

header.append_text("#undef MIN\n")
header.append_text("#undef MAX\n")
header.append_text("#undef ASSERT\n")
header.append_text("#undef SIZEOF\n")
header.append_text("#undef TRACE\n")

header.append_text("#define Scanner WL_Scanner\n")
header.append_text("#define Token WL_Token\n")
header.append_text("#define is_space is_space__wl\n")
header.append_text("#define is_digit is_digit__wl\n")
header.append_text("#define is_alpha is_alpha__wl\n")
header.append_text("#define is_printable is_printable__wl\n")
header.append_text("#define is_hex_digit is_hex_digit__wl\n")
header.append_text("#define hex_digit_to_int hex_digit_to_int__wl\n")
header.append_text("#define consume_str consume_str__wl\n")

header.append_file("3p/wl.h")
header.append_file("3p/wl.c")

header.append_text("#undef Scanner\n")
header.append_text("#undef Token\n")
header.append_text("#undef is_space\n")
header.append_text("#undef is_digit\n")
header.append_text("#undef is_alpha\n")
header.append_text("#undef is_printable\n")
header.append_text("#undef is_hex_digit\n")
header.append_text("#undef hex_digit_to_int\n")

header.append_text("#undef MIN\n")
header.append_text("#undef MAX\n")
header.append_text("#undef ASSERT\n")
header.append_text("#undef SIZEOF\n")

header.append_file("3p/crypt_blowfish.h")
header.append_file("3p/crypt_blowfish.c")
header.append_file("src/main.c")

header.append_text("#endif // CWEB_IMPLEMENTATION\n")
header.save("cweb.h")
