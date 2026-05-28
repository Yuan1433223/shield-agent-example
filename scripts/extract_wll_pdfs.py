"""
提取 kk安全运维出的文档/证据模型/王龙龙 下全部 PDF 文字内容到 docs/experts/WLL。

输出结构镜像源目录树：
  docs/experts/WLL/攻击案例/Domain/<stem>.txt
  docs/experts/WLL/攻击案例/IP/<stem>.txt
  docs/experts/WLL/非攻击案例/...

用法：
  uv run python scripts/extract_wll_pdfs.py
  uv run python scripts/extract_wll_pdfs.py --src <自定义源目录> --dst <自定义输出目录>
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pymupdf  # PyMuPDF


SOURCE_DEFAULT = Path(__file__).parents[2] / "kk安全运维出的文档" / "证据模型" / "王龙龙"
DEST_DEFAULT = Path(__file__).parents[1] / "docs" / "experts" / "WLL"


def extract_pdf(pdf_path: Path) -> str:
    """提取单个 PDF 全部页面文字，保留段落换行。"""
    doc = pymupdf.open(str(pdf_path))
    pages: list[str] = []
    for page in doc:
        # "text" 模式保留原始换行，blocks 排序保证阅读顺序
        text = page.get_text("text", sort=True)
        if text.strip():
            pages.append(text)
    doc.close()
    return "\n\n".join(pages)


def process(src: Path, dst: Path) -> None:
    pdfs = sorted(src.rglob("*.pdf"))
    if not pdfs:
        print(f"未找到 PDF：{src}", file=sys.stderr)
        sys.exit(1)

    ok = err = 0
    for pdf in pdfs:
        rel = pdf.relative_to(src)          # e.g. 攻击案例/IP/xxx.pdf
        out = dst / rel.with_suffix(".txt")
        out.parent.mkdir(parents=True, exist_ok=True)

        try:
            text = extract_pdf(pdf)
            out.write_text(text, encoding="utf-8")
            print(f"  ok  {rel}")
            ok += 1
        except Exception as exc:
            print(f"  ERR {rel}: {exc}", file=sys.stderr)
            err += 1

    print(f"\n完成：{ok} 成功，{err} 失败  →  {dst}")


def main() -> None:
    parser = argparse.ArgumentParser(description="提取王龙龙 PDF 文字内容")
    parser.add_argument("--src", type=Path, default=SOURCE_DEFAULT)
    parser.add_argument("--dst", type=Path, default=DEST_DEFAULT)
    args = parser.parse_args()

    if not args.src.exists():
        print(f"源目录不存在：{args.src}", file=sys.stderr)
        sys.exit(1)

    print(f"源：{args.src}")
    print(f"目标：{args.dst}\n")
    process(args.src, args.dst)


if __name__ == "__main__":
    main()