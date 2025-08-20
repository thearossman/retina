This didn't work, likely because a generic `impl` block is pulling something into scope that it shouldn't.
However, it's super unclear to me how to fix it. 

The error looks something like this:

  = note: some arguments are omitted. use `--verbose` to show all linker arguments
  = note: /usr/bin/ld: /home/tcr6/retina/target/debug/build/retina-core-e0bb152a27606b9d/out/libinlined.a(c4427b042533b9aa-inlined.o): in function `rte_mempool_get_ops':
          /usr/local/include/rte_mempool.h:754:(.text.unlikely.rte_mempool_get_ops.part.0+0x28): undefined reference to `__rte_panic'
          /usr/bin/ld: /home/tcr6/retina/target/debug/build/retina-core-e0bb152a27606b9d/out/libinlined.a(c4427b042533b9aa-inlined.o): in function `rte_lcore_id':
          /usr/local/include/rte_lcore.h:80:(.text.rte_pktmbuf_free_+0x12f): undefined reference to `per_lcore__lcore_id'
          /usr/bin/ld: /home/tcr6/retina/target/debug/build/retina-core-e0bb152a27606b9d/out/libinlined.a(c4427b042533b9aa-inlined.o): in function `rte_mempool_ops_enqueue_bulk':
          /usr/local/include/rte_mempool.h:850:(.text.rte_pktmbuf_free_+0x1e7): undefined reference to `rte_mempool_ops_table'
          /usr/bin/ld: /usr/local/include/rte_mempool.h:850:(.text.rte_pktmbuf_free_+0x220): undefined reference to `rte_mempool_ops_table'
          /usr/bin/ld: /home/tcr6/retina/target/debug/build/retina-core-e0bb152a27606b9d/out/libinlined.a(c4427b042533b9aa-inlined.o): in function `rte_lcore_id':
          /usr/local/include/rte_lcore.h:80:(.text.rte_pktmbuf_free_+0x2a7): undefined reference to `per_lcore__lcore_id'
          /usr/bin/ld: /usr/local/include/rte_lcore.h:80:(.text.rte_pktmbuf_free_+0x4b9): undefined reference to `per_lcore__lcore_id'
          /usr/bin/ld: /home/tcr6/retina/target/debug/build/retina-core-e0bb152a27606b9d/out/libinlined.a(c4427b042533b9aa-inlined.o): in function `rte_mempool_ops_enqueue_bulk':
          /usr/local/include/rte_mempool.h:850:(.text.rte_pktmbuf_free_+0x545): undefined reference to `rte_mempool_ops_table'
          /usr/bin/ld: /usr/local/include/rte_mempool.h:850:(.text.rte_pktmbuf_free_+0x59c): undefined reference to `rte_mempool_ops_table'
          /usr/bin/ld: /usr/local/include/rte_mempool.h:850:(.text.rte_pktmbuf_free_+0x611): undefined reference to `rte_mempool_ops_table'
          /usr/bin/ld: /usr/local/include/rte_mempool.h:850:(.text.rte_pktmbuf_free_+0x65e): undefined reference to `rte_mempool_ops_table'
          collect2: error: ld returned 1 exit status
          
  = note: some `extern` functions couldn't be found; some native libraries may need to be installed or have their path specified
  = note: use the `-l` flag to specify native libraries to link
  = note: use the `cargo:rustc-link-lib` directive to specify the native libraries to link with Cargo (see https://doc.rust-lang.org/cargo/reference/build-scripts.html#rustc-link-lib)
