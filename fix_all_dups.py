import io
import re

P = "web/control.html"
s = io.open(P, encoding="utf-8").read()

# Find the main script tag
script_start = s.index('<script>', 1362)
script_end = s.index('</script>', s.index('<script>', 1362))
script = s[script_start + 8:script_end]

# Remove ALL duplicate function definitions - keep only the FIRST occurrence of each
# Strategy: Find all function definitions, keep first, remove rest

functions_to_dedup = [
    'function ensureAuth\(',
    'function showLogin\(',
    'function hideLogin\(',
    'async function login\(',
]

for pattern in functions_to_dedup:
    positions = [m.start() for m in re.finditer(pattern, script)]
    print(f"{pattern}: {len(positions)} occurrences at {positions}")
    if len(positions) > 1:
        # Remove from last to first to preserve positions
        for pos in reversed(positions[1:]):
            end_idx = script.index("}", pos) + 1
            while end_idx < len(script) and script[end_idx] != "\n":
                end_idx += 1
            end_idx += 1
            script = script[:pos] + script[end_idx:]
            print(f"  Removed duplicate at {pos}")

# Rebuild
script_start = s.index('<script>', 1362)
script_end = s.index('</script>', s.index('<script>', 1362))
new_s = s[:script_start + 8] + script + s[script_end:]

io.open(P, "w", encoding="utf-8").write(new_s)
print("Fixed all duplicate functions")