import sys
import os
from subprocess import call

def build_embedded_go_codes(filename):
    """
    Extract embedded Go code snippets from a Markdown file and compile each of them.

    Args:
        filename (str): The path to the Markdown file containing embedded Go code snippets.

    Returns:
        list: A list of output Go file names that were created and compiled.

    Raises:
        ValueError: If no Go code block is found in the file.
    """

    with open(filename, 'r') as f:
        flag = False  # Tracks if inside Go block
        codes = []   # Go codes from embedded
        snippet_counter = 1
        out_files = []

        for line in f.readlines():
            if line.strip() == '```go':
                flag = True
                codes = []
            elif line.strip() == '```' and flag:
                out = f'temporary_{snippet_counter}.go'
                out_files.append(out)

                if os.path.exists(out):
                    os.remove(out)

                with open(out, 'w') as g:
                    g.write("".join(codes))

                snippet_counter += 1
                flag = False
            elif flag:
                codes.append(line)

        if not out_files:
            raise ValueError("No Go code block found in the markdown file (argument).")

        return out_files


if __name__ == '__main__':
    filename = sys.argv[1]
    out_files = build_embedded_go_codes(filename)

    ret_code = 0
    for out in out_files:
        ret = call(['go', 'build', '-o', out.replace('.go', ''), out])
        if ret != 0:
            ret_code = ret
        os.remove(out)
        if os.path.exists(out.replace('.go', '')):
            os.remove(out.replace('.go', ''))

    sys.exit(ret_code)
