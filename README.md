# 论文阅读

### [PACMem: Enforcing Spatial and Temporal Memory Safety via ARM Pointer Authentication](./PACMem/PACMem.md)
PACMem通过以一种巧妙的方式消除元数据传播来提高性能，即使用COTS硬件功能——ARM PA将指针的元数据编码为指针。  
在PACMem中，指针与其所指向的内存位置一起加密。当代码尝试访问指针指向的内存位置时，系统会解密指针，并验证其与指向的内存位置是否匹配。如果不匹配，则系统会中断该操作，从而防止缓冲区溢出和其他类似的内存攻击...

### [ASan&HWASan](./ASan/ASan.md)
Address Sanitizer, 是一种 (C/C++) 内存地址错误检查器. 这个东西在编译时和运行时发挥作用. 它被集成进了各大编译器之中。  
介绍了ASan和HWASan的原理与区别。  

### [Performance-Optimal Read-Only Transactions](./Performance-Optimal%20Read-Only%20Transactions/README.md)
本文提出了对于只读事务的NOCS理论，阐明了只读事务不能对于最优性能和最强一致性（即事务的隔离级别）兼而有之。  







