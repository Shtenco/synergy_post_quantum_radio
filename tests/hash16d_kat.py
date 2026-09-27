import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "legacy/recovered/SYNERGY_ORCH/l1/hash16d.py"
VECTORS = ROOT / "tests/vectors/hash16d_recovered_kat.json"

spec = importlib.util.spec_from_file_location("recovered_hash16d", SOURCE)
module = importlib.util.module_from_spec(spec)
assert spec.loader is not None
spec.loader.exec_module(module)

vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
engine = module.Hash16D()

for vector in vectors["vectors"]:
    data = bytes.fromhex(vector["input_hex"])
    got_fast = engine.hash(data, fast=True)
    got_full = engine.hash(data, fast=False)
    assert got_fast == vector["fast_hash16d"], (vector, got_fast)
    assert got_full == vector["full_hash16d"], (vector, got_full)

print(f"HASH16D KAT PASS: {len(vectors['vectors'])} vectors")
