import re

with open('src/endpoint.rs', 'r') as f:
    text = f.read()

# Make sure we don't accidentally double-add
# We just add stream_id and offset right after window_size: xxx, if it doesn't already have stream_id

def fix_match(m):
    block = m.group(0)
    if 'stream_id' not in block:
         # find the last comma before } usually window_size: ...,
         # or just insert before '}'
         block = re.sub(r'(window_size:\s*[^,}\n]+),?', r'\1,\n            stream_id: 0,\n            offset: 0,', block)
    return block

# Find structs
fixed = re.sub(r'PacketHeader\s*\{[^\}]+\}', fix_match, text)

with open('src/endpoint.rs', 'w') as f:
    f.write(fixed)
