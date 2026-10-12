"""Independent CVSS v3.1 base score from the FIRST specification (Sections 7.1, 7.4, Appendix A)."""
import itertools, json, sys
W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44},
     "PRU": {"N": .85, "L": .62, "H": .27}, "PRC": {"N": .85, "L": .68, "H": .5},
     "UI": {"N": .85, "R": .62}, "CIA": {"H": .56, "L": .22, "N": 0}}
def roundup(v):
    i = round(v * 100000)
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0
def score(vec):
    m = dict(p.split(":") for p in vec.split("/")[1:])
    iss = 1 - (1 - W["CIA"][m["C"]]) * (1 - W["CIA"][m["I"]]) * (1 - W["CIA"][m["A"]])
    changed = m["S"] == "C"
    imp = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
    ex = 8.22 * W["AV"][m["AV"]] * W["AC"][m["AC"]] * W["PRC" if changed else "PRU"][m["PR"]] * W["UI"][m["UI"]]
    if imp <= 0: return 0.0
    return roundup(min(1.08 * (imp + ex), 10)) if changed else roundup(min(imp + ex, 10))
if __name__ == "__main__":
    from cvss import CVSS3
    space = ["CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in zip(["AV","AC","PR","UI","S","C","I","A"], combo))
             for combo in itertools.product("NALP", "LH", "NLH", "NR", "UC", "HLN", "HLN", "HLN")]
    lib_bad = [(v, score(v), CVSS3(v).scores()[0]) for v in space if abs(score(v) - CVSS3(v).scores()[0]) > 1e-9]
    cases = [c for c in json.load(open(sys.argv[1])) if c["vector"].startswith("CVSS:3.1/")]
    fix_bad = [(c["vector"], c["score"], score(c["vector"])) for c in cases if abs(score(c["vector"]) - c["score"]) > 1e-9]
    print(json.dumps({"base_space": len(space), "library_disagrees_with_spec": len(lib_bad), "examples": lib_bad[:3],
                      "reference_file_v31_cases": len(cases), "file_disagrees_with_spec": fix_bad}, indent=1))
