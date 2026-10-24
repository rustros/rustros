# Boot once and print the boot log (up to the rescue prompt).
import sys, os
S = os.path.dirname(os.path.abspath(__file__))
mode = sys.argv[1]; sys.argv = ["test.py"] + sys.argv[1:]
src = open(f"{S}/test.py").read()
__file__ = f"{S}/test.py"
exec(src.split('check("boot"')[0])
ok = wait_for("rescue> ", 120)
import re
print(re.sub(r"key=\S+", "key=***", clean(log)))
q.kill()
