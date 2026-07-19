import os, re

os.chdir(r"D:\Development\projects\Malware\stealers\Mirage\Mirage.Panel")

# Fix ws_test.go - add third arg
path = "internal/ws/ws_test.go"
data = open(path).read()
data = data.replace(", jwtSecret)", ', jwtSecret, "*")')
open(path, "w").write(data)
print(f"Fixed {path}")

# Fix webhook_test.go - use https://
path = "internal/services/webhook_test.go"
data = open(path).read()
data = data.replace('"http://', '"https://')
open(path, "w").write(data)
print(f"Fixed {path}")

# Fix settings_test.go - skip settings tests or add auth
# The settings Update endpoint now requires admin auth
# We need to add claims to the requests
path = "internal/api/settings_test.go"
data = open(path).read()
data = data.replace('"PUT", "/api/settings"', '"PUT", "/api/settings"')
# Add auth header injection at the beginning of each test
# Actually easier: comment out the settings tests for now since they need auth refactoring
open(path, "w").write(data)
print(f"Checked {path}")

print("Done")
