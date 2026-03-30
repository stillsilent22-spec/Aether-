@echo off
cd /d "c:\Users\kalle\Downloads\Aether_master (1) (1)\aether_final"
python -m pip install networkx -q
echo === networkx installed ===
python -m pytest tests/ --tb=short -q > test_results.txt 2>&1
type test_results.txt
echo === DONE ===
