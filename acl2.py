from typing import List, Tuple, Union

#Khai báo kiểu dữ liệu
Range = Tuple[int, int]
RangeList = List[Range] #danh sách nhiều khoảng cho IP

# Định nghĩa ACL rule
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

#Định nghĩa verification rule (traffic cần kiểm chứng)
class Packet:
    def __init__(self, srcIP: RangeList, srcPort, dstIP: RangeList, dstPort, protocol):
        self.srcIP = srcIP
        self.srcPort = srcPort
        self.dstIP = dstIP
        self.dstPort = dstPort
        self.protocol = protocol


#Hàm xử lý khoảng
"""
    Gộp các khoảng chồng lấn/ kề nhau thành khoảng lớn hơn
    Đảm bảo danh sách khoảng sắp xếp và rời nhau
"""
def normalize_ranges(rlist: RangeList) -> RangeList:
    if not rlist: return []
    rlist = sorted(rlist)
    res = [list(rlist[0])]
    for a, b in rlist[1:]:
        c, d = res[-1]
        if a <= d + 1:
            res[-1][1] = max(d, b)
        else:
            res.append([a, b])
    return [(a, b) for a, b in res]

#Trả về khoảng giao nhau giữa a và b
def intersect_ranges(a: Range, b: Range) -> RangeList:
    lo, hi = max(a[0], b[0]), min(a[1], b[1])
    return [(lo, hi)] if lo <= hi else []

#Thực hiện phép Cut lấy hiệu hai khoảng a\b
def subtract_one(a: Range, b: Range) -> RangeList:
    ax, ay = a; bx, by = b
    if by < ax or bx > ay: return [a]
    out = []
    if bx > ax: out.append((ax, bx - 1))
    if by < ay: out.append((by + 1, ay))
    return out

#Giao của hai danh sách khoảng 
def intersect_rangelists(A: RangeList, B: RangeList) -> RangeList:
    A, B = normalize_ranges(A), normalize_ranges(B)
    out = []
    for a in A:
        for b in B:
            out += intersect_ranges(a, b)
    return normalize_ranges(out)

#Hiệu A\B (loại bỏ tất cả khoảng B ra khỏi A)
def subtract_rangelists(A: RangeList, B: RangeList) -> RangeList:
    A, B = normalize_ranges(A), normalize_ranges(B)
    cur = A[:]
    for b in B:
        nxt = []
        for a in cur:
            nxt += subtract_one(a, b)
        cur = nxt
        if not cur: break
    return normalize_ranges(cur)


# Mảnh traffic cần test (một mảnh nhỏ của Verification rule)
"""
 Vì khi cắt, R1 có thể tách ra thành R1_rs, R1_hit, R1_rd...."""
class VerPiece:
    def __init__(self, srcIP: RangeList, dstIP: RangeList,
                 srcPort="any", dstPort="any", protocol="any",
                 expect_action="permit", tag="R"):
        self.srcIP = normalize_ranges(srcIP)
        self.dstIP = normalize_ranges(dstIP)
        self.srcPort = srcPort
        self.dstPort = dstPort
        self.protocol = protocol
        self.expect_action = expect_action #hành động mong đợi
        self.tag = tag #nhãn để in log dễ theo dõi

    #Kiểm tra xem mảnh có rỗng ( không còn IP hợp lệ)
    def is_empty(self) -> bool:
        return not self.srcIP or not self.dstIP

    #Kiểm tra có giao với rule ACL theo cả srcIP và dstIP không
    def intersects_rule(self, rule: Rule) -> bool:
        return bool(intersect_rangelists(self.srcIP, rule.srcIP)) and \
               bool(intersect_rangelists(self.dstIP, rule.dstIP))


#Cut(Rk,L)
def cut_piece_by_rule(piece: VerPiece, rule: Rule):
    inter_src = intersect_rangelists(piece.srcIP, rule.srcIP)
    #Nếu không giao theo srcIP-> rule không bắt được gì->toàn bộ piece vẫn tồn tại
    if not inter_src:
        return [], [piece]

    #Nếu giao: tách phần không giao -> đưa vào remainer
    rem_src = subtract_rangelists(piece.srcIP, inter_src)
    remainder = [VerPiece([rs], piece.dstIP,
                          piece.srcPort, piece.dstPort,
                          piece.protocol, piece.expect_action,
                          tag=piece.tag + "_rs") for rs in rem_src]

    #Nếu không giao theo dstIP -> toàn bộ phần inter_src x dstIP chưa bị xử lý, vẫn remainder
    inter_dst = intersect_rangelists(piece.dstIP, rule.dstIP)
    if not inter_dst:
        remainder.append(VerPiece(inter_src, piece.dstIP,
                                  piece.srcPort, piece.dstPort,
                                  piece.protocol, piece.expect_action,
                                  tag=piece.tag + "_keep"))
        return [], remainder

    #Nếu có giao theo dstIP: tách phần ngoài giao->remainder
    rem_dst = subtract_rangelists(piece.dstIP, inter_dst)
    for rd in rem_dst:
        remainder.append(VerPiece(inter_src, [rd],
                                  piece.srcPort, piece.dstPort,
                                  piece.protocol, piece.expect_action,
                                  tag=piece.tag + "_rd"))

    #Phần giao cả src và dst -> rule này sẽ bắt
    handled = [VerPiece(inter_src, inter_dst,
                        piece.srcPort, piece.dstPort,
                        piece.protocol, piece.expect_action,
                        tag=piece.tag + "_hit")]
    return handled, remainder


# Thuật toán kiểm chứng
def verify_by_partition(acl_rules: List[Rule], verification: VerPiece, verbose: bool = True):
    #RL tập mảnh cần xét, ban đầu chỉ có 1 verification
    RL = [verification]

    #Duyệt lần lượt từng rule ACL 
    for i, L in enumerate(acl_rules, 1):
        if verbose:
            print(f"\n=== ACL Rule {i} ({L.name}) action={L.action} ===")
        new_RL = []
        for piece in RL:
            if piece.is_empty():
                continue
            # Nếu không giao với L thì giữ nguyên 
            if not piece.intersects_rule(L):
                new_RL.append(piece)
                if verbose:
                    print(f"  [keep] {piece.tag}: no-intersect with {L.name}")
                continue
            
            #Nếu có phần giao
            handled, remainder = cut_piece_by_rule(piece, L)
            for h in handled:
                if verbose:
                    # in ra [hit]
                    print(f"  [hit]  {piece.tag} ∩ {L.name} -> "
                          f"src={h.srcIP} dst={h.dstIP} "
                          f"expect={h.expect_action} vs {L.action}")
                    #so sánh expect_action với L.action
                    #Nếu khác -> conflict -> trả về Fail ngay
                if h.expect_action != L.action:
                    return False, f"Conflict at {L.name}: expect {h.expect_action} but ACL={L.action}"
                
            #remainder chưa xử lý tiếp tục xuống rule dưới
            new_RL.extend([r for r in remainder if not r.is_empty()])
        RL = new_RL
        #Nếu không còn mảnh nào -> PASS sớm
        if not RL:
            return True, None
        """
        HẾT ACL còn mảnh chưa xử lý:
            ACL mặc định deny
            Nếu mong đợi deny -> PASS
            Nếu mong đợi permit -> Fail
        """
    for piece in RL:
        if piece.expect_action != "deny":
            return False, "Conflict with default deny"
    return True, None


#Nhập rangelist từ bàn phìm
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

#Nhập port/protocol
def input_value(name: str):
    raw = input(f"{name} (số hoặc any): ").strip().lower()
    if raw == "any": return "any"
    try:
        return int(raw)
    except: return raw

#Nhập đầy đủ một ACL rule
def input_rule(idx: int) -> Rule:
    print(f"\n--- ACL Rule {idx} ---")
    srcIP = input_rangelist("srcIP")
    srcPort = input_value("srcPort")
    dstIP = input_rangelist("dstIP")
    dstPort = input_value("dstPort")
    protocol = input_value("protocol")
    action = input("action (permit/deny): ").strip().lower()
    return Rule(srcIP, srcPort, dstIP, dstPort, protocol, action, f"L{idx}")

#Nhập một verification rules
def input_verification(idx: int) -> VerPiece:
    print(f"\n--- Verification {idx} ---")
    srcIP = input_rangelist("srcIP")
    srcPort = input_value("srcPort")
    dstIP = input_rangelist("dstIP")
    dstPort = input_value("dstPort")
    protocol = input_value("protocol")
    expect = input("expected action (permit/deny): ").strip().lower()
    return VerPiece(srcIP, dstIP, srcPort, dstPort, protocol, expect, f"R{idx}")


# =======================
# Main
# =======================
if __name__ == "__main__":
    #Nhập số lượng ACL rules
    n = int(input("Số ACL rules: "))
    #Nhập từng rule
    rules = [input_rule(i+1) for i in range(n)]

    #NHập số lượng verification rules
    m = int(input("\nSố verification rules: "))
    #Nhập từng rule
    verifications = [input_verification(j+1) for j in range(m)]

    print("\n=== Kết quả kiểm chứng ===")
    #Chạy kiểm chứng từng verification
    for v in verifications:
        ok, where = verify_by_partition(rules, v, verbose=True)
        #In ra Pass/fail kèm thông tin conflict 
        print(f"\n[Verification {v.tag}] => {'PASS' if ok else 'FAIL'} {where or ''}")
