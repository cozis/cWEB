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
        #self.out += "#line 1 \"" + file + "\"\n"
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
source.append_text("#define HTTP_NOINCLUDE\n")
source.append_file("3p/wl.h")
source.append_file("3p/chttp.h")
source.append_file("3p/chttp.c")
source.append_file("3p/crypt_blowfish.h")
source.append_file("3p/crypt_blowfish.c")
source.append_file("3p/wl.c")
source.append_file("src/main.c")
source.save("cweb.c")
