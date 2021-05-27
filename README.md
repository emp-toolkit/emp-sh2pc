# emp-sh2pc
![arm](https://github.com/emp-toolkit/emp-sh2pc/workflows/arm/badge.svg)
![x86](https://github.com/emp-toolkit/emp-sh2pc/workflows/x86/badge.svg)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

# Installation
1. `wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py`
2. `python install.py -install -tool -ot -sh2pc`
    1. By default it will build for Release. `-DCMAKE_BUILD_TYPE=[Release|Debug]` option is also available.
    2. No sudo? Change [`CMAKE_INSTALL_PREFIX`](https://cmake.org/cmake/help/v2.8.8/cmake.html#variable%3aCMAKE_INSTALL_PREFIX).
    3. On Mac [homebrew](https://brew.sh/) is needed for installation. 
## Test

* If you want to test the code in local machine, type

   `./run ./bin/[binaries] 12345 [more opts]`
* IF you want to test the code over two machine, type

  `./bin/[binaries] 1 12345 [more opts]` on one machine and 
  
  `./bin/[binaries] 2 12345 [more opts]` on the other.
  
  IP address is hardcoded in the test files.

* example_semi_honest should run as 
	`./bin/example 1 12345 123 & ./bin/example 2 12345 124`
	
	because different parrties needs different numbers

### Question
Please send email to wangxiao@cs.northwestern.edu

## Acknowledgement
This work was supported in part by the National Science Foundation under Awards #1111599 and #1563722.
