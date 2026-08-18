from pathlib import Path
from docx import Document
from docx.oxml.ns import qn

path = Path(r"E:\DATTTN\TTTN\DamMinhLinh_ A03_BCDK1_ChuongII_hoanthien_v2.docx")
doc = Document(path)

# Trong CT_RPr, w:color phải đứng trước nhóm spacing/size/highlight/underline.
after_color = {
    qn("w:spacing"), qn("w:w"), qn("w:kern"), qn("w:position"),
    qn("w:sz"), qn("w:szCs"), qn("w:highlight"), qn("w:u"),
    qn("w:effect"), qn("w:bdr"), qn("w:shd"), qn("w:fitText"),
    qn("w:vertAlign"), qn("w:rtl"), qn("w:cs"), qn("w:em"),
    qn("w:lang"), qn("w:eastAsianLayout"), qn("w:specVanish"),
    qn("w:oMath"),
}


def normalize(root):
    for rpr in root.findall(".//" + qn("w:rPr")):
        color = rpr.find(qn("w:color"))
        if color is None:
            continue
        rpr.remove(color)
        index = len(rpr)
        for i, child in enumerate(rpr):
            if child.tag in after_color:
                index = i
                break
        rpr.insert(index, color)


normalize(doc._element.body)
for rid in ("rId28", "rId29"):
    normalize(doc.part.rels[rid].target_part.element)
doc.save(path)
