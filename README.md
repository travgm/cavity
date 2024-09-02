This directory contains the fractioned cavity loader implementation based off of smelly_vx's paper in
vxug vol 1 zine. 

Improvements Implemented:
- Hashing of the executable file and we store the original hash in the fraction #0 header.
- Salt is computed from header
- Encrypting each fraction with AES-256
- Validating that each file is actually a fraction
- You can put it to any directory (builder) and it verifies files and puts them in the right order by qsort
- NOT Implemented (You can use original method with this builder and breaker basically if you like): Load each fraction into RWX memory and executing it once reassembled

Written by Travis Montoya "travgm" (hexproof.sh)
