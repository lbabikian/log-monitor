"""
src/tailer.py
Implements log file reading utilities, including:
- static reader (read_lines)
- tail-like follower (follow)
"""
import time
import os
from typing import Iterable

def read_lines(path: str) -> Iterable[str]:
    """Reads all lines from a file once (for batch processing)"""
    with open(path, 'r', errors='ignore') as f:
        for line in f:
            yield line.rstrip('\n')


def follow(path: str) -> Iterable[str]:
    """
    Continuously follows a file like `tail -f`
    Yields new lines as they're appended
    """
    with open(path, 'r', errors='ignore') as f:
        # start at EOF so we only see new appended lines
        f.seek(0, os.SEEK_END)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.2) # Prevent busy waiting
                continue
            yield line.rstrip('\n')