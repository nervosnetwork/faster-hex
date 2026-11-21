"""Apply only the specified control to an isolated source export."""
def select(source, role, env):
    variant = env.get(role.upper() + "_CONTROL")
    if not variant:
        return
    if variant == "version":
        path = source / "Cargo.toml"
        old, new = 'version = "2.0.0"', 'version = "2.1.0"'
    elif variant == "bulk32":
        path = source / "src/encode.rs"
        old, new = '    if src.len() > 32 {\n        return encode_neon_bulk', '    if src.len() >= 32 {\n        return encode_neon_bulk'
    else:
        raise ValueError(variant)
    text = path.read_text()
    assert text.count(old) == 1
    path.write_text(text.replace(old, new))
