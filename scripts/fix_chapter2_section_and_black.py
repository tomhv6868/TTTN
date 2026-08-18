from copy import deepcopy
from pathlib import Path

from docx import Document
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

path = Path(r"E:\DATTTN\TTTN\DamMinhLinh_ A03_BCDK1_ChuongII_hoanthien_v2.docx")
doc = Document(path)


def find_paragraph(text):
    return next(p for p in doc.paragraphs if p.text.strip() == text)


chapter2 = find_paragraph("CHƯƠNG 2. MÔ HÌNH ĐỀ XUẤT")
chapter3 = find_paragraph("CHƯƠNG 3. KẾT QUẢ THỰC NGHIỆM VÀ THẢO LUẬN")


def force_black(root):
    for run in root.findall(".//" + qn("w:r")):
        rpr = run.find(qn("w:rPr"))
        if rpr is None:
            rpr = OxmlElement("w:rPr")
            run.insert(0, rpr)
        color = rpr.find(qn("w:color"))
        if color is None:
            color = OxmlElement("w:color")
            rpr.append(color)
        color.set(qn("w:val"), "000000")
        color.attrib.pop(qn("w:themeColor"), None)
        color.attrib.pop(qn("w:themeTint"), None)
        color.attrib.pop(qn("w:themeShade"), None)
    for ppr in root.findall(".//" + qn("w:pPr")):
        mark = ppr.find(qn("w:rPr"))
        if mark is not None:
            color = mark.find(qn("w:color"))
            if color is None:
                color = OxmlElement("w:color")
                mark.append(color)
            color.set(qn("w:val"), "000000")


# Đặt toàn bộ chữ trong Chương II thành màu đen, gồm heading, code, bảng và caption.
node = chapter2._p
while node is not None and node is not chapter3._p:
    force_black(node)
    node = node.getnext()

# Tìm sectPr đang kết thúc section chung Chương II–III (header Chương III rId30/rId31).
body = doc._element.body
chapter3_section_properties = None
for element in body:
    ppr = element.find(qn("w:pPr")) if element.tag == qn("w:p") else None
    sectpr = ppr.find(qn("w:sectPr")) if ppr is not None else None
    if sectpr is None:
        continue
    refs = {
        ref.get(qn("w:type")): ref.get(qn("r:id"))
        for ref in sectpr.findall(qn("w:headerReference"))
    }
    if refs.get("default") == "rId30" and refs.get("first") == "rId31":
        chapter3_section_properties = sectpr
        break
if chapter3_section_properties is None:
    raise RuntimeError("Không tìm thấy section properties của Chương III")

# Không chèn lặp nếu script được chạy lại.
previous = chapter3._p.getprevious()
existing_break = None
if previous is not None and previous.tag == qn("w:p"):
    ppr = previous.find(qn("w:pPr"))
    existing_break = ppr.find(qn("w:sectPr")) if ppr is not None else None

if existing_break is None:
    break_p = OxmlElement("w:p")
    ppr = OxmlElement("w:pPr")
    new_sectpr = deepcopy(chapter3_section_properties)

    for ref in list(new_sectpr.findall(qn("w:headerReference"))):
        new_sectpr.remove(ref)
    default_ref = OxmlElement("w:headerReference")
    default_ref.set(qn("w:type"), "default")
    default_ref.set(qn("r:id"), "rId28")
    first_ref = OxmlElement("w:headerReference")
    first_ref.set(qn("w:type"), "first")
    first_ref.set(qn("r:id"), "rId29")
    new_sectpr.insert(0, first_ref)
    new_sectpr.insert(0, default_ref)

    section_type = new_sectpr.find(qn("w:type"))
    if section_type is None:
        section_type = OxmlElement("w:type")
        # Sau header/footer references và trước page size.
        insert_at = len(new_sectpr.findall(qn("w:headerReference"))) + len(new_sectpr.findall(qn("w:footerReference")))
        new_sectpr.insert(insert_at, section_type)
    section_type.set(qn("w:val"), "nextPage")

    ppr.append(new_sectpr)
    break_p.append(ppr)
    chapter3._p.addprevious(break_p)

# Header Chương II cũng được khóa màu đen.
for rid in ("rId28", "rId29"):
    force_black(doc.part.rels[rid].target_part.element)

doc.save(path)
