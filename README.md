This directory contains the fractioned cavity loader implementation based off of smelly_vx's paper in
vxug vol 1 zine. 

We have implemented:
- Hashing of the executable file and we store the original hash in the fraction #0 header.
- Encrypting each fraction
- Validating that each file is a fraction
- Load each fraction into RWX memory and executing it once reassembled

Then this was all put together with some other techniques for the flx.c virus.
