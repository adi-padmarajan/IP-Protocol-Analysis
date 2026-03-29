#!/usr/bin/env python3
"""Extract text from assignment PDF files."""
import subprocess
import sys
import os

os.chdir('/Users/adip/Desktop/IP-Protocol-Analysis')

for pdf in ['p3-Fall2026.pdf', 'Q&A-Assignment 3.pdf']:
    print('=' * 70)
    print(f'  {pdf}')
    print('=' * 70)

    # Try pdftotext first (comes with poppler)
    r = subprocess.run(['pdftotext', pdf, '-'], capture_output=True, text=True)
    if r.returncode == 0 and r.stdout.strip():
        print(r.stdout)
        continue

    # Try python libraries
    try:
        import PyPDF2
        reader = PyPDF2.PdfReader(pdf)
        for page in reader.pages:
            print(page.extract_text())
        continue
    except ImportError:
        pass

    try:
        import pdfminer.high_level
        text = pdfminer.high_level.extract_text(pdf)
        print(text)
        continue
    except ImportError:
        pass

    print(f"Could not extract text from {pdf}. Need pdftotext, PyPDF2, or pdfminer.")
