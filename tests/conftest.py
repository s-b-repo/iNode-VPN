import os
import sys

# h3csvpn lives under backends/ in this unified repo layout
sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "backends"))
