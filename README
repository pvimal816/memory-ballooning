**Application level memory ballooning**

Memory balloning is a technique used to eliminate the overprovision of host memory in VMs. It works by allocating unused memory in VM to the "balloon" which gaurantees that other application in the VM are not accessing it. Then, this part of the host memory can be used by the hypervisor as per its needs.

In this work we are implementing the idea of memory ballooning at the application level. We provide a kernel API by which the applications can register for ballooning. So, in the event of a memory pressure the kernel can send the SIGBALLOON(the custom signal) signal to those applications. We also provide the system calls by which the applications can pass the memory pages which it wants the kernel to swap out.

**Usecases**
The kernel uses general policy to select the victim pages to be swapped out. Whereas the memory access pattern varies across the applications. So, we expect the performance improvement by delegating the selection of victim pages to the application.
