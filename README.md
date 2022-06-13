TELEPORT is a new operating system feature in disaggregated data centers (DDCs) that provides compute pushdown support.
It is capable of moving computation between resource pools efficiently.
Data-intensive systems can leverage this feature to minimize data movement overhead and maximize the elastic benefits of DDCs.
Refer to [our SIGMOD 2022 paper](https://dl.acm.org/doi/10.1145/3514221.3517856) for more details.

# Setup

This prototype is built on top of LegoOS. It includes `teleport/` that implements two new system calls, `managers/processor/teleport` that implements compute-side data synchronization, and `managers/memory/teleport` that implements memory-side responsibilities.
Refer to [the LegoOS repo](https://github.com/WukLab/LegoOS) (or [its readme](LegoOS_README.md) cached in this repo) for how to set up a LegoOS cluster.  It follows the same steps to compile and set up TELEPORT. Below are a few important parameters:

## Infiniband IDs
Make sure the Infiniband LID of each machine is hardcoded correctly in `net/lego/fit_machine.c`. Otherwise, the servers won't be able to connect to each other.

## Application
Make sure the binary path of the application on the storage node and its arguments are correctly specified in `managers/processor/core.c`.

## Compute-local cache size
This parameter is specified in the GRUB configuration file (`/boot/grub/grub.cfg` in Ubuntu 18.04). It determines how much local memory the compute node can use. Generally, the lower this value, the more frequently the compute node must access remote memory, hence higher disaggregation overhead.

# Usage
## Configuration
`include/teleport/teleport_config.h` has a few configuration options for TELEPORT, including how it encodes page information in data synchronization before and after pushdown and the number of user contexts that it can spawn in parallel.

## Porting the Application
To push down a memory-intensive component in the application, the user should wrap the component as a function and use the following system call to offload it to the memory node:
```C
long pushdown(void *func, void *arg, int flags);
```
For example, if an aggregation operator is wrapped as `long agg_func(struct agg_arg *arg)`, then calling `pushdown(agg_func, agg_arg_ptr, flags)` will execute `arg_func(agg_arg_ptr)` on the memory side, where `agg_arg_ptr` is the pointer to a `struct agg_arg` object and `flags` specifies how this pushdown call synchronizes data.

The other new system call `syncmem` can be used for manual data synchronization when the coherence protocol is relaxed.
It is defined as follows:
```C
long syncmem(void *addr, size_t size, int flags);
```
where `addr` and `size` are the address and the size of the data to be synchronized respectively. 

## Customizing A Pushdown
`teleport/pushdown/pushdown.c` shows a few data synchronization options that the user can set in the `flags` argument in `pushdown`. We support both eager and lazy synchronization as well as cache coherence and its relaxation.

# Hardware
Same as LegoOS, TELEPORT has strong requirements on the hardware. We have been developing and testing TELEPORT using the hardware as follows:
- CPU: Intel Xeon E5-2630L
- NIC: Mellanox MCX354A-FCBT CX354A ConnectX-3 VPI EDR InfiniBand
- Switch: Mellanox MSB7780-ES2F Switch EDR InfiniBand