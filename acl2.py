from typing import List, Tuple, Union

# ======================
#  Định nghĩa kiểu dữ liệu
# ======================
Range = Tuple[int, int]
RangeList = List[Range]

class Rule:
    def __init__(self, srcIP: RangeList, srcPort: Union[int, str],
                 dstIP: RangeList, dstPort: Union[int, str],
                 protocol: Union[str, None], action: str, name: str = ""):
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.protocol = protocol
        self.action = action
        self.name = name


class VerPiece:
    def __init__(self, srcIP: RangeList, dstIP: RangeList,
                 srcPort="any", dstPort="any", protocol="any",
                 expect_action="permit", tag="R"):
        self.srcIP = normalize_ranges(srcIP)
        self.dstIP = normalize_ranges(dstIP)
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.protocol = protocol
        self.expect_action = expect_action
        self.tag = tag

    def is_empty(self) -> bool:
        return not self.srcIP or not self.dstIP

    def intersects_rule(self, rule: Rule) -> bool:
        return bool(intersect_rangelists(self.srcIP, rule.srcIP)) and \
               bool(intersect_rangelists(self.dstIP, rule.dstIP))


# ======================
#  Hàm xử lý khoảng
# ======================

def normalize_ranges(rlist: RangeList) -> RangeList:
    """Gộp các khoảng chồng lấn/ kề nhau"""
    if not rlist:
        return []
    rlist = sorted(rlist)
    res = [list(rlist[0])]
    for a, b in rlist[1:]:
        c, d = res[-1]
        if a <= d + 1:
            res[-1][1] = max(d, b)
        else:
            res.append([a, b])
    return [(a, b) for a, b in res]


def intersect_ranges(a: Range, b: Range) -> RangeList:
    lo, hi = max(a[0], b[0]), min(a[1], b[1])
    return [(lo, hi)] if lo <= hi else []


def subtract_one(a: Range, b: Range) -> RangeList:
    ax, ay = a
    bx, by = b
    if by < ax or bx > ay:
        return [a]
    out = []
    if bx > ax:
        out.append((ax, bx - 1))
    if by < ay:
        out.append((by + 1, ay))
    return out


def intersect_rangelists(A: RangeList, B: RangeList) -> RangeList:
    A, B = normalize_ranges(A), normalize_ranges(B)
    out = []
    for a in A:
        for b in B:
            out += intersect_ranges(a, b)
    return normalize_ranges(out)


def subtract_rangelists(A: RangeList, B: RangeList) -> RangeList:
    A, B = normalize_ranges(A), normalize_ranges(B)
    cur = A[:]
    for b in B:
        nxt = []
        for a in cur:
            nxt += subtract_one(a, b)
        cur = nxt
        if not cur:
            break
    return normalize_ranges(cur)


# ======================
#  Cắt đa chiều (srcIP × dstIP)
# ======================

def cut_piece_by_rule(piece: VerPiece, rule: Rule, verbose=False):
    """
    Cắt piece theo rule — đa chiều (srcIP × dstIP)
    Trả về:
        handled: phần bị rule xử lý
        remainder: phần còn lại (chưa bị rule xử lý)
    """
    handled = []
    remainder = []

    for src_seg in piece.srcIP:
        for dst_seg in piece.dstIP:
            inter_src = intersect_rangelists([src_seg], rule.srcIP)
            inter_dst = intersect_rangelists([dst_seg], rule.dstIP)

            # Không giao nhau
            if not inter_src or not inter_dst:
                remainder.append(VerPiece([src_seg], [dst_seg],
                                           piece.srcPort, piece.dstPort,
                                           piece.protocol, piece.expect_action,
                                           tag=piece.tag + "_keep"))
                continue

            # Phần giao
            h_piece = VerPiece(inter_src, inter_dst,
                               piece.srcPort, piece.dstPort,
                               piece.protocol, piece.expect_action,
                               tag=piece.tag + "_hit")
            handled.append(h_piece)

            # Phần dư theo src và dst
            rem_src = subtract_rangelists([src_seg], inter_src)
            rem_dst = subtract_rangelists([dst_seg], inter_dst)

            for rs in rem_src:
                remainder.append(VerPiece([rs], [dst_seg],
                                           piece.srcPort, piece.dstPort,
                                           piece.protocol, piece.expect_action,
                                           tag=piece.tag + "_rs"))

            for rd in rem_dst:
                remainder.append(VerPiece(inter_src, [rd],
                                           piece.srcPort, piece.dstPort,
                                           piece.protocol, piece.expect_action,
                                           tag=piece.tag + "_rd"))

            if verbose:
                print(f"    [INTERSECT] src={inter_src} dst={inter_dst}")
                if rem_src:
                    print(f"    [SUBRULE-src] còn lại theo src={rem_src}")
                if rem_dst:
                    print(f"    [SUBRULE-dst] còn lại theo dst={rem_dst}")

    return handled, remainder


# ======================
#  Thuật toán kiểm chứng chính
# ======================

def verify_by_partition(acl_rules: List[Rule], verification: VerPiece, verbose: bool = True):
    RL = [verification]
    all_subrules = []

    for i, L in enumerate(acl_rules, 1):
        if verbose:
            print(f"\n=== ACL Rule {i} ({L.name}) action={L.action} ===")

        new_RL = []
        for piece in RL:
            if piece.is_empty():
                continue

            if not piece.intersects_rule(L):
                new_RL.append(piece)
                if verbose:
                    print(f"  [KEEP] {piece.tag}: no-intersect with {L.name}")
                continue

            handled, remainder = cut_piece_by_rule(piece, L, verbose=verbose)

            # Phần giao (hit)
            for h in handled:
                if verbose:
                    print(f"  [HIT]  {piece.tag} ∩ {L.name} -> "
                          f"src={h.srcIP}, dst={h.dstIP}, "
                          f"expect={h.expect_action}, ACL={L.action}")
                all_subrules.append((h.tag, h.srcIP, h.dstIP, "INTERSECT"))
                if h.expect_action != L.action:
                    print(f"  Conflict: expect={h.expect_action}, ACL={L.action}")
                    return False, f"Conflict at {L.name}: expect {h.expect_action} but ACL={L.action}"

            # Phần dư (sub rules)
            for r in remainder:
                if verbose:
                    print(f"  [SUBRULE] {r.tag}: src={r.srcIP}, dst={r.dstIP}")
                all_subrules.append((r.tag, r.srcIP, r.dstIP, "SUBRULE"))
                if not r.is_empty():
                    new_RL.append(r)

        RL = new_RL
        if not RL:
            print("\n Verification passed: tất cả các packet đã được xử lý.")
            print_subrules_table(all_subrules)
            return True, None

    # Kiểm tra phần còn lại cuối cùng
    for piece in RL:
        if piece.expect_action != "deny":
            print_subrules_table(all_subrules)
            return False, "Conflict with default deny"

    print_subrules_table(all_subrules)
    return True, None


# ======================
#  In bảng Sub Rules
# ======================

def print_subrules_table(subrules):
    print("\n BẢNG SUB RULES:")
    print("{:<12} {:<25} {:<25} {:<10}".format("Tag", "Src Range", "Dst Range", "Type"))
    print("-" * 80)
    for tag, src, dst, typ in subrules:
        print("{:<12} {:<25} {:<25} {:<10}".format(tag, str(src), str(dst), typ))


# ======================
#  Nhập dữ liệu từ người dùng
# ======================

def input_rangelist(name: str) -> RangeList:
    raw = input(f"{name} (vd: 10-20,30-40 hoặc any): ").strip().lower()
    if raw == "any":
        return [(0, 2**32 - 1)]
    out = []
    for p in raw.split(","):
        if "-" in p:
            a, b = p.split("-")
            out.append((int(a), int(b)))
        else:
            v = int(p)
            out.append((v, v))
    return out


def input_value(name: str):
    raw = input(f"{name} (số hoặc any): ").strip().lower()
    if raw == "any":
        return "any"
    try:
        return int(raw)
    except:
        return raw


def input_rule(idx: int) -> Rule:
    print(f"\n--- ACL Rule {idx} ---")
    srcIP = input_rangelist("srcIP")
    srcPort = input_value("srcPort")
    dstIP = input_rangelist("dstIP")
    dstPort = input_value("dstPort")
    protocol = input_value("protocol")
    action = input("action (permit/deny): ").strip().lower()
    return Rule(srcIP, srcPort, dstIP, dstPort, protocol, action, f"L{idx}")


def input_verification(idx: int) -> VerPiece:
    print(f"\n--- Verification {idx} ---")
    srcIP = input_rangelist("srcIP")
    srcPort = input_value("srcPort")
    dstIP = input_rangelist("dstIP")
    dstPort = input_value("dstPort")
    protocol = input_value("protocol")
    expect = input("expected action (permit/deny): ").strip().lower()
    return VerPiece(srcIP, dstIP, srcPort, dstPort, protocol, expect, f"R{idx}")


# ======================
#  MAIN
# ======================

if __name__ == "__main__":
    n = int(input("Số ACL rules: "))
    rules = [input_rule(i + 1) for i in range(n)]

    m = int(input("\nSố verification rules: "))
    verifications = [input_verification(j + 1) for j in range(m)]

    print("\n=== KẾT QUẢ KIỂM CHỨNG ===")
    for v in verifications:
        ok, where = verify_by_partition(rules, v, verbose=True)
        print(f"\n[Verification {v.tag}] => {'PASS' if ok else 'FAIL'} {where or ''}")
