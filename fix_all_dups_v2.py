import io
import re

P = "web/control.html"
s = io.open(P, encoding="utf-8").read()

# Find the main script tag boundaries
script_start_tag = s.index('<script>', 1362)
script_end_tag = s.index('</script>', script_start_tag)
script_start = script_start_tag + 8  # after '<script>'
script_end = script_end_tag
script = s[script_start:script_end]

print(f"Script length: {len(script)}")

# Remove duplicates from the script content
def remove_duplicates(content, pattern):
    positions = [m.start() for m in re.finditer(pattern, content)]
    if len(positions) <= 1:
        return content
    # Remove from last to first
    for pos in reversed(positions[1:]):
        end_idx = content.index("}", pos) + 1
        while end_idx < len(content) and content[end_idx] != "\n":
            end_idx += 1
        end_idx += 1
        content = content[:pos] + content[end_idx:]
    return content

patterns = [
    r'function ensureAuth\(',
    r'function showLogin\(',
    r'function hideLogin\(',
    r'async function login\(',
]

for pattern in patterns:
    script = remove_duplicates(script, pattern)

# Rebuild full HTML
new_s = s[:script_start] + script + s[script_end:]

io.open("web/control.html", "w", encoding="utf-8").write(new_s)
print("Fixed all duplicate functions in HTML")