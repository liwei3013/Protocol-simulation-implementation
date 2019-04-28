# Protocol-simulation-implementation
how to use please refer to howuse.pdf
There are three points that need improvement and attention in this experiment.

  1. Solve how to compress a point on the ECC into a number belonging to Z_p^*. And then you can recover this point without loss.
     Use function int lsb=epoint(epoint * p,big x, big x) to compress a point epoint * p into a 512-bit x and a int number lsb. Then if you want to      restore this point epoint * p , use function epoint_set(big x, big x, int lsb, epoint * p). These functions also have a corresponding C++          interface in ECn.
     
     
  2. The output form of e(d_{ui},H_{00}(ID_{sj}))  is a+bi , where a, b are 512 bits of n-residue.
    
     
  3. In the case of AES 128 bit security, the related hash functions defined in ssp_pair.cpp output 256 bits. In order to be able to            completely XOR(⊕) the 512-bit d_{ui}, e(*,*) output through the 1,2 step, PWD_{ui}, PBIO_{ui} can be amplified at the corresponding        step by using the  shs512_init*, shs512_process*, and shs512_hash* functions. 
  
For example, in the original paper G_{ui}=d_{ui}⊕PWD_{ui},  the implementation algorithm is G_{ui}=fun1(d_{ui})⊕fun3(PWD_{ui}), the original paper R_{sj}=e(d_{ui},H_{00}(ID_{sj}))⊕PBIO_{ui}⊕PWD_{ui}, and its implementation algorithm is R_{sj}_a=a⊕fun3(PBIO_{ui})⊕fun3(PWD_{ui}),R_{sj}_b=b⊕fun3(PBIO_{ui})⊕fun3(PWD_{ui}), where fun1 is defined according to the 1 step, fun3 is defined according to the 3 step.
