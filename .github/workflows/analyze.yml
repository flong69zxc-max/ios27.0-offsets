name: Extract iOS 27 Kernel Offsets
on: workflow_dispatch

jobs:
  analyze:
    runs-on: ubuntu-latest
    timeout-minutes: 15
    steps:
      - uses: actions/checkout@v4

      - name: Cache Ghidra
        uses: actions/cache@v4
        with:
          path: ghidra_11.0.3_PUBLIC
          key: ghidra-11.0.3-linux-v1

      - name: Install deps
        run: |
          sudo apt-get update
          sudo apt-get install -y openjdk-17-jdk-headless wget unzip

      - name: Setup Ghidra
        run: |
          if [ ! -d ghidra_11.0.3_PUBLIC ]; then
            wget -q https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.3_build/ghidra_11.0.3_PUBLIC_20240410.zip
            unzip -q ghidra_11.0.3_PUBLIC_20240410.zip
          fi
          echo "GHIDRA=$(pwd)/ghidra_11.0.3_PUBLIC" >> $GITHUB_ENV

      - name: Prepare kernel
        run: |
          unzip -o kernel.zip
          ls -la kernel.raw

      - name: Run Ghidra (symbols only)
        run: |
          mkdir -p /tmp/proj
          timeout 600 $GHIDRA/support/analyzeHeadless /tmp/proj ios27 \
            -import kernel.raw \
            -noanalysis \
            -scriptPath scripts \
            -postScript find_offsets.py \
            -deleteProject || true

      - name: Show result
        if: always()
        run: |
          if [ -f offsets.txt ]; then
            echo "=== offsets.txt ==="
            cat offsets.txt
          else
            echo "[-] no offsets.txt"
            ls -la
          fi

      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: offsets-${{ github.run_number }}
          path: offsets.txt
          if-no-files-found: warn
