# Constantine
This is the future home of `Constantine`: a compiler-based system to automatically harden programs against microarchitectural side channels.

`Constantine` pursues a radical design point where secret dependent control and data flows are completely linearized: all the possible secret-dependent code/data memory accesses are always executed regardless of the particular secret value encountered.
Thanks to carefully designed optimizations such as *just-in-time loop linearization* and *aggressive function cloning*, `Constantine` provides a scalable solution, while supporting all the common programming constructs in real-world software. 

This is the high-level architecture of `Constantine`:

<br/><br/>
<img src="https://user-images.githubusercontent.com/18199462/115702424-37eb6780-a369-11eb-88a5-83e6eb28e05f.png">
<br/><br/>

`Constantine` outperforms prior comprehensive solutions in terms of both performance and compatibility, while also providing stronger security guarantees. For example, we show `Constantine` yields overheads as low as 16% for cache-line attacks on standard benchmarks. Moreover, `Constantine` can protect ECDSA signatures in the [wolfSSL](https://www.wolfssl.com/) embedded library to complete a constant-time modular multiplication in 8 ms.

The design behind `Constantine` is described in the paper *Constantine: Automatic Side-Channel Resistance Using Efficient Control and Data Flow Linearization* (preprint available [here](http://www.diag.uniroma1.it/~delia/papers/ccs21.pdf) or on [arXiv](https://arxiv.org/abs/2104.10749)) which will appear in the [ACM CCS 2021](https://www.sigsac.org/ccs/CCS2021/) conference. 

## Access to code
The code will be released by the conference date.

## Cite
```
@inproceedings{constantine,
    author = {Borrello, Pietro and D'Elia, Daniele Cono and Querzoni, Leonardo and Giuffrida, Cristiano},
    title = {Constantine: Automatic Side-Channel Resistance Using Efficient Control and Data Flow Linearization},
    year = {2021},
    publisher = {Association for Computing Machinery},
    booktitle = {Proceedings of the 2021 ACM SIGSAC Conference on Computer and Communications Security},
    location = {Seoul, South Korea},
    series = {CCS '21},
    doi={10.1145/3460120.3484583},
}
```
