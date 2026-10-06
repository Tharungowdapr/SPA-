import io
import re

P = "web/control.html"
s = io.open(P, encoding="utf-8").read()

# Find the main script tag (the large one at ~1362)
script_start = s.index('<script>', 1362)
script_end = s.index('</script>', s.index('<script>', 1362))
script = s[script_start + 8:script_end]

# Remove duplicate function definitions - keep only the first occurrence
# Pattern: find all function definitions and remove duplicates

# For ensureAuth - keep first, remove rest
ensureAuth_positions = [m.start() for m in re.finditer(r'function ensureAuth\(\)', script)]
print(f"ensureAuth positions: {ensureAuth_positions}")
if len(ensureAuth_positions) > 1:
    for pos in reversed(ensureAuth_positions[1:]):
        end_idx = script.index("}", pos) + 1
        while end_idx < len(script) and script[end_idx] != "\n":
            end_idx += 1
        end_idx += 1
        script = script[:pos] + script[end_idx:]
        print(f"Removed duplicate ensureAuth at {pos}")

# For showLogin - keep first, remove rest
showLogin_positions = [m.start() for m in re.finditer(r'function showLogin\(\)', script)]
print(f"showLogin positions: {showLogin_positions}")
if len(showLogin_positions) > 1:
    for pos in reversed(showLogin_positions[1:]):
        end_idx = script.index("}", pos) + 1
        while end_idx < len(script) and script[end_idx] != "\n":
            end_idx += 1
        end_idx += 1
        script = script[:pos] + script[end_idx:]
        print(f"Removed duplicate showLogin at {pos}")

# For login - keep first, remove rest
login_positions = [m.start() for m in re.finditer(r'async function login\(\)', script)]
print(f"login positions: {login_positions}")
if len(login_positions) > 1:
    for pos in reversed(login_positions[1:]):
        end_idx = script.index("}", pos) + 1
        while end_idx < len(script) and script[end_idx] != "\n":
            end_idx += 1
        end_idx += 1
        script = script[:pos] + script[end_idx:]
        print(f"Removed duplicate login at {pos}")

# For hideLogin - keep first, remove rest
hideLogin_positions = [m.start() for m in re.finditer(r'function hideLogin\(\)', script)]
print(f"hideLogin positions: {hideLogin_positions}")
if len(hideLogin_positions) > 1:
    for pos in reversed(hideLogin_positions[1:]):
        end_idx = script.index("}", pos) + 1
        while end_idx < len(script) and script[end_idx] != "\n":
            end_idx += 1
        end_idx += 1
        script = script[:pos] + script[end_idx:]
        print(f"Removed duplicate hideLogin at {pos}")

# Also fix the last showLogin if it's missing LOGIN_HTML assignment
# The first showLogin should have the correct implementation
first_showLogin = script.index("function showLogin()")
end_idx = script.index("}", first_showLogin) + 1
first_showLogin_code = script[first_showLogin:end_idx]
print(f"First showLogin: {first_showLogin_code[:200]}")

# Rebuild
script_start = s.index('<script>', 1362)
script_end = s.index('</script>', s.index('<script>', 1362))
new_s = s[:script_start + 8] + script + s[script_end:]

io.open("web/control.html", "w", encoding="utf-8").write(new_s)
print("Fixed duplicate functions")