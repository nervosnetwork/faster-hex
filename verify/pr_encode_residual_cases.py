revisions = {
    "release":"6d84260fe321669e7f93ecfb8aecb4db0f582f14",
    "version":"f83d1075a7945c2dfe56ee7b94d9b6b1783cdf93",
    "narrow":"976abc9503a22c1b24beb54182add19af097f098",
    "pr":"25cfd8eb6a4cd8257a96fabaf73771cabcced4b4",
    "scoped":"2680b238f7c5c211aed329a70c8a30c669570ec9",
    "scalar":"9fe0c2fd7dbe306579fbd6e0a96a6be98ac48845",
    "vector":"7e56debd7ed955d2ad8aee35804bb6e52f29b075",
}
cases = [
    ("full_buffer",65,"buffer"),("qualified_decode",4096,"valid"),("ckb_caller",32,"plain"),
    ("full_format",4096,"display"),("vec_read_slice",32,"escaped"),("vec_read_slice",32,"plain"),
    ("vec_round_slice",32,"escaped"),("vec_round_slice",32,"plain"),
    ("vec_round_slice",4096,"escaped"),("vec_round_slice",4096,"plain"),
]
cases += [("full_buffer",n,"buffer") for n in (8,16,32,33,63,64,71,72,73,79,80,128,4096,65536)]
cases += [("full_upper",n,"buffer") for n in (65,79)]
cases += [("gix_prefix",n,"sha1-adopt") for n in (0,7,12,40)]
cases += [("gix_prefix",n,"sha256-adopt") for n in (7,64)]
cases += [("prefix_buffer",n,"buffer") for n in (4,7,64)]
cases += [("vec_write",4096,"plain"),("array_read_slice",32,"escaped"),("array_round_slice",4096,"plain"),
          ("ckb_caller",4096,"plain"),("gix_caller",20,"parse"),("full_format",32,"alternate"),
          ("append_call",32,"first"),("validate_call",32,"last")]
assert len(cases)==len(set(cases))==43
controls=("release","pr","scalar","vector")
pairs=[("scoped","aa"),*((k,k+"_control") for k in controls),
       ("release","version"),("release","pr"),("release","narrow"),("release","scoped"),("pr","scoped"),
       *((a,b) for a in ("release","version","pr","narrow","scoped") for b in ("scalar","vector")),
       ("scalar","vector")]
